"""
JSON-RPC streaming parser for proper message handling
Implements proper JSON-RPC message streaming
"""

import json
import asyncio
from typing import AsyncIterator, Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)


class JSONStreamParser:
    """
    Streaming JSON parser that properly handles JSON-RPC messages
    Similar to serde_json::Deserializer in Rust
    """
    
    def __init__(self, buffer_size: int = 8192):
        self.buffer_size = buffer_size
        self.buffer = b''
        self.decoder = json.JSONDecoder()
        
    async def parse_stream(self, reader: asyncio.StreamReader) -> AsyncIterator[Dict[str, Any]]:
        """
        Parse JSON objects from an async stream
        
        Args:
            reader: Async stream reader
            
        Yields:
            Parsed JSON objects
        """
        while True:
            # Read chunk from stream
            try:
                chunk = await reader.read(self.buffer_size)
                if not chunk:
                    # End of stream
                    if self.buffer.strip():
                        logger.warning(f"Incomplete JSON in buffer: {self.buffer[:100]}")
                    break
                
                self.buffer += chunk
                
                # Process buffer for complete JSON objects
                async for obj in self._process_buffer():
                    yield obj
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error reading stream: {e}")
                # Try to recover by clearing buffer
                self.buffer = b''
    
    async def _process_buffer(self) -> AsyncIterator[Dict[str, Any]]:
        """
        Extract complete JSON objects from buffer
        
        Yields:
            Complete JSON objects
        """
        while self.buffer:
            # Skip whitespace at beginning
            idx = 0
            while idx < len(self.buffer) and self.buffer[idx:idx+1].isspace():
                idx += 1
            
            if idx >= len(self.buffer):
                self.buffer = b''
                return
            
            # Try to decode JSON from current position
            try:
                text = self.buffer[idx:].decode('utf-8', errors='ignore')
                obj, end_idx = self.decoder.raw_decode(text)
                
                # Successfully parsed an object
                yield obj
                
                # Remove parsed portion from buffer
                self.buffer = self.buffer[idx + end_idx:]
                
            except json.JSONDecodeError as e:
                # Not enough data for complete JSON object
                if idx > 0:
                    # Remove leading whitespace
                    self.buffer = self.buffer[idx:]
                
                # Check if buffer is too large (potential attack or corruption)
                if len(self.buffer) > 1024 * 1024:  # 1MB limit
                    logger.error("Buffer too large, clearing")
                    self.buffer = b''
                
                # Wait for more data
                return
            except UnicodeDecodeError as e:
                # Corrupted data, try to recover
                logger.error(f"Unicode decode error: {e}")
                # Find next potential JSON start
                next_brace = self.buffer.find(b'{', idx + 1)
                if next_brace > 0:
                    self.buffer = self.buffer[next_brace:]
                else:
                    self.buffer = b''
                return


class LineDelimitedJSONParser:
    """
    Parser for line-delimited JSON (JSONL format)
    Fallback parser if streaming fails
    """
    
    def __init__(self):
        self.buffer = b''
        
    async def parse_stream(self, reader: asyncio.StreamReader) -> AsyncIterator[Dict[str, Any]]:
        """
        Parse line-delimited JSON from stream
        
        Args:
            reader: Async stream reader
            
        Yields:
            Parsed JSON objects
        """
        while True:
            try:
                line = await reader.readline()
                if not line:
                    break
                
                line = line.strip()
                if not line:
                    continue
                
                try:
                    obj = json.loads(line)
                    yield obj
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse JSON line: {e}")
                    logger.debug(f"Invalid line: {line[:100]}")
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error reading line: {e}")


class AdaptiveJSONParser:
    """
    Adaptive parser that tries streaming first, falls back to line-delimited
    """
    
    def __init__(self):
        self.streaming_parser = JSONStreamParser()
        self.line_parser = LineDelimitedJSONParser()
        self.use_streaming = True
        self.parse_errors = 0
        self.max_errors = 3
        
    async def parse_stream(self, reader: asyncio.StreamReader) -> AsyncIterator[Dict[str, Any]]:
        """
        Parse JSON from stream with adaptive strategy
        
        Args:
            reader: Async stream reader
            
        Yields:
            Parsed JSON objects
        """
        if self.use_streaming:
            try:
                async for obj in self.streaming_parser.parse_stream(reader):
                    yield obj
                    self.parse_errors = 0  # Reset on success
            except Exception as e:
                logger.warning(f"Streaming parser failed, switching to line-delimited: {e}")
                self.parse_errors += 1
                
                if self.parse_errors >= self.max_errors:
                    self.use_streaming = False
                    logger.info("Permanently switching to line-delimited parser")
                    
                    # Fall back to line parser
                    async for obj in self.line_parser.parse_stream(reader):
                        yield obj
        else:
            # Use line parser
            async for obj in self.line_parser.parse_stream(reader):
                yield obj


class JSONRPCStreamWriter:
    """
    Write JSON-RPC messages to stream with proper formatting
    """
    
    def __init__(self, writer: asyncio.StreamWriter, use_newlines: bool = True):
        self.writer = writer
        self.use_newlines = use_newlines
        
    async def write_message(self, message: Dict[str, Any]):
        """
        Write JSON-RPC message to stream
        
        Args:
            message: Message dictionary to write
        """
        try:
            # Serialize to JSON
            data = json.dumps(message, separators=(',', ':'))
            
            # Add newline if configured (most MCP servers expect this)
            if self.use_newlines:
                data += '\n'
            
            # Write to stream
            self.writer.write(data.encode('utf-8'))
            await self.writer.drain()
            
        except Exception as e:
            logger.error(f"Error writing message: {e}")
            raise
    
    async def close(self):
        """Close the writer stream"""
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception as e:
            logger.error(f"Error closing writer: {e}")