"""
Core DriftCop Proxy implementation with 4-task async architecture
"""

import asyncio
import sys
import os
import json
import subprocess
import signal
from pathlib import Path
from typing import Dict, Optional, Any, List
from dataclasses import dataclass, field
import logging
import multiprocessing as mp
from multiprocessing import shared_memory
import uuid

try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass  # Fall back to standard asyncio

from .message import MCPMessage, MessageParser, MessageDirection, MessageType
from .session import SessionManager
from .json_stream import JSONStreamParser, JSONRPCStreamWriter, AdaptiveJSONParser
from ..driftcop_interceptors.chain import InterceptorChain
from ..driftcop_storage.manager import StorageManager

logger = logging.getLogger(__name__)


class DriftCopProxy:
    """
    High-performance MCP proxy with 4-task async architecture
    Implements bidirectional message interception and security enforcement
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize proxy with configuration
        
        Args:
            config: Proxy configuration dictionary
        """
        self.config = config or {}
        self.session_manager = SessionManager()
        self.storage = StorageManager()
        
        # Message parser
        self.parser = MessageParser()
        
        # Async queues for message flow
        self.outbound_queue = asyncio.Queue(maxsize=self.config.get('queue_size', 10000))
        self.inbound_queue = asyncio.Queue(maxsize=self.config.get('queue_size', 10000))
        
        # Child process management
        self.child_process: Optional[subprocess.Popen] = None
        self.child_stdin: Optional[asyncio.StreamWriter] = None
        self.child_stdout: Optional[asyncio.StreamReader] = None
        self.child_stderr: Optional[asyncio.StreamReader] = None
        
        # Interceptor chain
        self.interceptor_chain = None
        
        # Statistics
        self.stats = {
            'messages_processed': 0,
            'messages_blocked': 0,
            'messages_transformed': 0,
            'errors': 0
        }
        
        # Shared memory for zero-copy optimization (if enabled)
        self.use_shared_memory = self.config.get('use_shared_memory', False)
        if self.use_shared_memory:
            self.shm_size = self.config.get('shm_size', 100 * 1024 * 1024)  # 100MB
            self.shm = shared_memory.SharedMemory(create=True, size=self.shm_size)
            self.ring_buffer = RingBuffer(self.shm, self.shm_size)
        
        # Process pool for CPU-intensive security analysis
        self.worker_count = self.config.get('worker_count', mp.cpu_count())
        self.security_pool = None
        
        # Shutdown event
        self.shutdown_event = asyncio.Event()
        
        # Hot reload manager
        self.hot_reload_manager = None
        if self.config.get('hot_reload', True):
            from ..driftcop_proxy.hot_reload import HotReloadManager
            self.hot_reload_manager = HotReloadManager(self)
        
    async def start(self, server_command: List[str], session_id: Optional[str] = None):
        """
        Start proxy with MCP server process
        
        Args:
            server_command: Command to start MCP server
            session_id: Optional session ID
        """
        # Create session
        if not session_id:
            session_id = str(uuid.uuid4())
        
        session = await self.session_manager.create_session(
            client_name=self.config.get('client_name', 'unknown'),
            server_config={'command': server_command},
            session_id=session_id
        )
        
        # Initialize interceptor chain
        await self._init_interceptor_chain(session)
        
        # Start child process
        await self._start_child_process(server_command)
        
        # Start worker pool
        if self.config.get('use_worker_pool', True):
            await self._init_worker_pool()
        
        # Start hot reload if enabled
        if self.hot_reload_manager:
            await self.hot_reload_manager.start()
            logger.info("Hot reload enabled for configuration changes")
        
        try:
            # Run 4 async tasks concurrently
            await asyncio.gather(
                self._outbound_receiver(),
                self._inbound_receiver(),
                self._outbound_transmitter(session),
                self._inbound_transmitter(session),
                self._stderr_reader(),
                self._monitor_child_process()
            )
        except asyncio.CancelledError:
            logger.info("Proxy tasks cancelled")
        finally:
            await self.shutdown()
    
    async def _start_child_process(self, command: List[str]):
        """Start MCP server as child process"""
        logger.info(f"Starting MCP server: {' '.join(command)}")
        
        # Create subprocess with pipes
        self.child_process = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, **self.config.get('env', {})}
        )
        
        self.child_stdin = self.child_process.stdin
        self.child_stdout = self.child_process.stdout
        self.child_stderr = self.child_process.stderr
        
        logger.info(f"MCP server started with PID: {self.child_process.pid}")
    
    async def _outbound_receiver(self):
        """
        Task 1: Read messages from stdin and queue for processing
        stdin → outbound_queue
        Uses proper JSON streaming for message parsing
        """
        logger.debug("Starting outbound receiver")
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        
        await asyncio.get_event_loop().connect_read_pipe(
            lambda: protocol, sys.stdin.buffer
        )
        
        # Use adaptive JSON parser for robust parsing
        json_parser = AdaptiveJSONParser()
        
        try:
            async for message_data in json_parser.parse_stream(reader):
                if self.shutdown_event.is_set():
                    break
                
                try:
                    # Create message from parsed JSON
                    message = MCPMessage.from_dict(message_data, MessageDirection.OUTBOUND)
                    
                    # Store request for correlation if needed
                    if message.type == MessageType.REQUEST and message.id:
                        self.session_manager.store_request(message)
                    
                    # Queue with backpressure handling
                    try:
                        await asyncio.wait_for(
                            self.outbound_queue.put(message),
                            timeout=1.0
                        )
                        logger.debug(f"Queued outbound message: {message.type} {message.method}")
                    except asyncio.TimeoutError:
                        logger.warning(f"Outbound queue full, dropping message: {message.method}")
                        self.stats['dropped'] += 1
                        
                except Exception as e:
                    logger.error(f"Failed to process outbound message: {e}")
                    self.stats['errors'] += 1
                    
        except asyncio.CancelledError:
            logger.debug("Outbound receiver cancelled")
        except Exception as e:
            logger.error(f"Fatal error in outbound receiver: {e}")
            self.shutdown_event.set()
        
        logger.debug("Outbound receiver stopped")
    
    async def _inbound_receiver(self):
        """
        Task 2: Read messages from child stdout and queue for processing
        child_stdout → inbound_queue
        Uses proper JSON streaming for message parsing
        """
        logger.debug("Starting inbound receiver")
        
        if not self.child_stdout:
            logger.error("No child stdout available")
            return
        
        # Use adaptive JSON parser for robust parsing
        json_parser = AdaptiveJSONParser()
        
        try:
            async for message_data in json_parser.parse_stream(self.child_stdout):
                if self.shutdown_event.is_set():
                    break
                
                try:
                    # Create message from parsed JSON
                    message = MCPMessage.from_dict(message_data, MessageDirection.INBOUND)
                    
                    # Correlate responses with requests
                    if message.type in (MessageType.RESPONSE_SUCCESS, MessageType.RESPONSE_FAILURE):
                        if message.id:
                            original_request = self.session_manager.get_request(message.id)
                            if original_request:
                                message._correlated_request = original_request
                    
                    # Queue with backpressure handling
                    try:
                        await asyncio.wait_for(
                            self.inbound_queue.put(message),
                            timeout=1.0
                        )
                        logger.debug(f"Queued inbound message: {message.type} {message.method}")
                    except asyncio.TimeoutError:
                        logger.warning(f"Inbound queue full, dropping message")
                        self.stats['dropped'] += 1
                        
                except Exception as e:
                    logger.error(f"Failed to process inbound message: {e}")
                    self.stats['errors'] += 1
                    
        except asyncio.CancelledError:
            logger.debug("Inbound receiver cancelled")
        except Exception as e:
            logger.error(f"Fatal error in inbound receiver: {e}")
            self.shutdown_event.set()
        
        logger.debug("Inbound receiver stopped")
    
    async def _outbound_transmitter(self, session):
        """
        Task 3: Process outbound messages through interceptors and send to child
        outbound_queue → interceptors → child_stdin
        """
        logger.debug("Starting outbound transmitter")
        
        while not self.shutdown_event.is_set():
            try:
                # Get message from queue with timeout
                message = await asyncio.wait_for(
                    self.outbound_queue.get(),
                    timeout=1.0
                )
                
                # Process through interceptors
                action = await self.interceptor_chain.process(message, session)
                
                # Handle action
                if action.should_forward():
                    # Send to child process
                    if self.child_stdin:
                        msg_to_send = action.get_message() or message
                        writer = JSONRPCStreamWriter(self.child_stdin)
                        await writer.write_message(msg_to_send.to_dict())
                        logger.debug(f"Sent to child: {message.type} {message.method}")
                
                elif action.should_return():
                    # Send synthetic response back
                    response = action.get_response()
                    sys.stdout.write(response.to_json() + '\n')
                    sys.stdout.flush()
                    logger.debug(f"Returned synthetic response for: {message.method}")
                
                elif action.should_block():
                    logger.info(f"Blocked outbound message: {message.method} - {action.reason}")
                    self.stats['messages_blocked'] += 1
                
                self.stats['messages_processed'] += 1
                
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in outbound transmitter: {e}")
                self.stats['errors'] += 1
        
        logger.debug("Outbound transmitter stopped")
    
    async def _inbound_transmitter(self, session):
        """
        Task 4: Process inbound messages through interceptors and send to stdout
        inbound_queue → interceptors → stdout
        """
        logger.debug("Starting inbound transmitter")
        
        while not self.shutdown_event.is_set():
            try:
                # Get message from queue with timeout
                message = await asyncio.wait_for(
                    self.inbound_queue.get(),
                    timeout=1.0
                )
                
                # Process through interceptors
                action = await self.interceptor_chain.process(message, session)
                
                # Handle action
                if action.should_forward():
                    # Send to stdout
                    data = action.get_message().to_json()
                    sys.stdout.write(data + '\n')
                    sys.stdout.flush()
                    logger.debug(f"Sent to stdout: {message.type} {message.method}")
                
                elif action.should_block():
                    logger.info(f"Blocked inbound message: {message.method} - {action.reason}")
                    self.stats['messages_blocked'] += 1
                
                self.stats['messages_processed'] += 1
                
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in inbound transmitter: {e}")
                self.stats['errors'] += 1
        
        logger.debug("Inbound transmitter stopped")
    
    async def _stderr_reader(self):
        """Read and log child stderr output"""
        if not self.child_stderr:
            return
        
        while not self.shutdown_event.is_set():
            try:
                line = await self.child_stderr.readline()
                if not line:
                    break
                
                # Log child stderr
                logger.info(f"Child stderr: {line.decode().strip()}")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error reading stderr: {e}")
    
    async def _monitor_child_process(self):
        """Monitor child process health"""
        if not self.child_process:
            return
        
        while not self.shutdown_event.is_set():
            try:
                # Check if child is still running
                returncode = self.child_process.returncode
                if returncode is not None:
                    logger.error(f"Child process exited with code: {returncode}")
                    self.shutdown_event.set()
                    break
                
                # Wait a bit before next check
                await asyncio.sleep(1)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error monitoring child: {e}")
    
    async def _init_interceptor_chain(self, session):
        """Initialize interceptor chain based on configuration"""
        from ..driftcop_interceptors.factory import InterceptorFactory
        
        factory = InterceptorFactory()
        interceptors = []
        
        # Get interceptor configuration
        interceptor_configs = self.config.get('interceptors', [])
        if not interceptor_configs:
            # Default interceptors
            interceptor_configs = [
                {'type': 'filter', 'config': {}},
                {'type': 'security', 'config': {
                    'use_worker_pool': self.config.get('use_worker_pool', True)
                }},
                {'type': 'sigstore', 'config': {}}
            ]
        
        # Load interceptors from config
        for interceptor_config in interceptor_configs:
            # Ensure security interceptor gets worker pool config
            if interceptor_config.get('type') == 'security':
                if 'config' not in interceptor_config:
                    interceptor_config['config'] = {}
                interceptor_config['config']['use_worker_pool'] = self.config.get('use_worker_pool', True)
            
            interceptor = factory.create(interceptor_config)
            if interceptor:
                interceptors.append(interceptor)
        
        # Create chain
        self.interceptor_chain = InterceptorChain(interceptors)
        logger.info(f"Initialized interceptor chain with {len(interceptors)} interceptors")
    
    async def _init_worker_pool(self):
        """Initialize multiprocessing pool for security analysis"""
        from ..driftcop_proxy.security_worker import init_worker, SecurityWorkerPool
        
        self.security_pool = mp.Pool(
            processes=self.worker_count,
            initializer=init_worker
        )
        
        # Create worker pool wrapper
        self.security_worker_pool = SecurityWorkerPool(self.security_pool)
        
        # Wire up worker pool to security interceptor if present
        if self.interceptor_chain:
            for interceptor in self.interceptor_chain.interceptors:
                # Find security interceptor
                if hasattr(interceptor, 'name') and interceptor.name == 'security':
                    if hasattr(interceptor, 'set_worker_pool'):
                        interceptor.set_worker_pool(self.security_worker_pool)
                        logger.info("Connected worker pool to security interceptor")
                        break
        
        logger.info(f"Initialized security worker pool with {self.worker_count} workers")
    
    async def shutdown(self):
        """Graceful shutdown"""
        logger.info("Shutting down proxy...")
        
        # Set shutdown event
        self.shutdown_event.set()
        
        # Stop hot reload manager
        if self.hot_reload_manager:
            await self.hot_reload_manager.stop()
        
        # Terminate child process
        if self.child_process:
            try:
                self.child_process.terminate()
                await asyncio.wait_for(self.child_process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                logger.warning("Child process didn't terminate, killing...")
                self.child_process.kill()
                await self.child_process.wait()
        
        # Shutdown worker pool
        if self.security_pool:
            self.security_pool.close()
            self.security_pool.join(timeout=5)
        
        # Clean up shared memory
        if self.use_shared_memory and hasattr(self, 'shm'):
            self.shm.close()
            self.shm.unlink()
        
        # Log statistics
        logger.info(f"Proxy statistics: {self.stats}")
        
        logger.info("Proxy shutdown complete")