"""
Python Function Interceptor for custom logic execution
Execute custom Python logic for message processing
"""

import ast
import sys
import json
import logging
import traceback
from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass
import hashlib
import tempfile
from pathlib import Path
import importlib.util

from .base import MessageInterceptor, InterceptorAction, ActionType
from ..driftcop_proxy.message import MCPMessage, MessageType, create_error_response
from ..driftcop_proxy.session import ProxySession

logger = logging.getLogger(__name__)


@dataclass
class PythonFunction:
    """Represents a Python function for message processing"""
    name: str
    code: str
    source: str  # 'inline', 'file', 'module'
    safe_mode: bool = True
    timeout: Optional[float] = None
    
    def get_hash(self) -> str:
        """Get hash of function code for caching"""
        return hashlib.md5(self.code.encode()).hexdigest()


class PythonFunctionInterceptor(MessageInterceptor):
    """
    Execute custom Python functions for message processing
    Provides a flexible API for custom message processing
    """
    
    name = "python_function"
    priority = 15  # Medium priority
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        
        # Function configuration
        self.script = config.get('script', '')
        self.script_file = config.get('script_file')
        self.module_path = config.get('module_path')
        self.function_name = config.get('function_name', 'process_message')
        
        # Execution configuration
        self.safe_mode = config.get('safe_mode', True)
        self.timeout = config.get('timeout', 5.0)
        self.cache_compiled = config.get('cache_compiled', True)
        self.allow_imports = config.get('allow_imports', [])
        
        # Load function
        self.function = self._load_function()
        
        # Compiled code cache
        self.compiled_cache = {}
        
        # Statistics
        self.executions = 0
        self.successes = 0
        self.failures = 0
        
        # Sandbox globals
        self.sandbox_globals = self._create_sandbox()
    
    def _load_function(self) -> Optional[PythonFunction]:
        """Load Python function from various sources"""
        if self.script:
            # Inline script
            return PythonFunction(
                name='inline',
                code=self.script,
                source='inline',
                safe_mode=self.safe_mode,
                timeout=self.timeout
            )
        
        elif self.script_file:
            # Load from file
            script_path = Path(self.script_file).expanduser()
            if not script_path.exists():
                logger.error(f"Script file not found: {script_path}")
                return None
            
            with open(script_path, 'r') as f:
                code = f.read()
            
            return PythonFunction(
                name=script_path.stem,
                code=code,
                source='file',
                safe_mode=self.safe_mode,
                timeout=self.timeout
            )
        
        elif self.module_path:
            # Load from module
            try:
                spec = importlib.util.spec_from_file_location(
                    "custom_interceptor",
                    self.module_path
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                if hasattr(module, self.function_name):
                    func = getattr(module, self.function_name)
                    # Wrap function code
                    code = f"""
def {self.function_name}(msg_direction, msg_type, raw_msg):
    import json
    # Call the loaded module function
    return module_func(msg_direction, msg_type, raw_msg)
"""
                    
                    return PythonFunction(
                        name=self.function_name,
                        code=code,
                        source='module',
                        safe_mode=False,  # Modules are trusted
                        timeout=self.timeout
                    )
                else:
                    logger.error(f"Function {self.function_name} not found in module")
                    
            except Exception as e:
                logger.error(f"Failed to load module: {e}")
                return None
        
        # Default function that allows everything
        default_code = """
def process_message(msg_direction, msg_type, raw_msg):
    # Default function - allow all messages
    return 'send'
"""
        return PythonFunction(
            name='default',
            code=default_code,
            source='default',
            safe_mode=True
        )
    
    def _create_sandbox(self) -> Dict[str, Any]:
        """Create sandboxed globals for script execution"""
        # Safe built-ins only
        safe_builtins = {
            'True': True,
            'False': False,
            'None': None,
            'abs': abs,
            'all': all,
            'any': any,
            'bool': bool,
            'dict': dict,
            'enumerate': enumerate,
            'filter': filter,
            'float': float,
            'int': int,
            'len': len,
            'list': list,
            'map': map,
            'max': max,
            'min': min,
            'print': print,  # Captured for debugging
            'range': range,
            'round': round,
            'set': set,
            'sorted': sorted,
            'str': str,
            'sum': sum,
            'tuple': tuple,
            'type': type,
            'zip': zip,
        }
        
        # Create sandbox
        sandbox = {
            '__builtins__': safe_builtins,
            'json': json,  # Allow JSON operations
            'action': 'send',  # Default action
            'metadata': {},  # For storing metadata
            'log': logger.info,  # Allow logging
        }
        
        # Add allowed imports if configured
        if not self.safe_mode:
            sandbox['__builtins__'] = __builtins__
            
        for module_name in self.allow_imports:
            try:
                module = __import__(module_name)
                sandbox[module_name] = module
            except ImportError:
                logger.warning(f"Could not import allowed module: {module_name}")
        
        return sandbox
    
    def _validate_code(self, code: str) -> bool:
        """Validate Python code for safety"""
        if not self.safe_mode:
            return True
        
        try:
            tree = ast.parse(code)
            
            # Check for dangerous operations
            for node in ast.walk(tree):
                # Allow json import in safe mode
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name != 'json':
                            logger.warning(f"Import {alias.name} not allowed in safe mode")
                            return False
                elif isinstance(node, ast.ImportFrom):
                    if node.module not in ['json', 'datetime']:
                        logger.warning(f"Import from {node.module} not allowed in safe mode")
                        return False
                
                # No file operations
                if isinstance(node, ast.Name) and node.id in ['open', 'file']:
                    logger.warning("File operations not allowed in safe mode")
                    return False
                
                # No exec/eval
                if isinstance(node, ast.Name) and node.id in ['exec', 'eval', 'compile']:
                    logger.warning("Dynamic execution not allowed in safe mode")
                    return False
                
                # No system operations
                if isinstance(node, ast.Attribute):
                    if hasattr(node.value, 'id') and node.value.id in ['os', 'sys', 'subprocess']:
                        logger.warning("System operations not allowed in safe mode")
                        return False
            
            return True
            
        except SyntaxError as e:
            logger.error(f"Syntax error in Python code: {e}")
            return False
    
    def _execute_function(
        self,
        function: PythonFunction,
        msg_direction: str,
        msg_type: str,
        raw_msg: str
    ) -> str:
        """
        Execute Python function with standard API
        
        Args:
            function: Python function to execute
            msg_direction: 'inbound' or 'outbound'
            msg_type: Message type string
            raw_msg: Raw JSON message
            
        Returns:
            Action string: 'send', 'drop', or 'modify'
        """
        # Get or compile code
        code_hash = function.get_hash()
        
        if self.cache_compiled and code_hash in self.compiled_cache:
            compiled_code = self.compiled_cache[code_hash]
        else:
            # Validate code in safe mode
            if function.safe_mode and not self._validate_code(function.code):
                logger.error("Code validation failed")
                return 'drop'
            
            try:
                compiled_code = compile(function.code, '<interceptor>', 'exec')
                if self.cache_compiled:
                    self.compiled_cache[code_hash] = compiled_code
            except Exception as e:
                logger.error(f"Failed to compile Python code: {e}")
                return 'drop'
        
        # Prepare sandbox with message data
        sandbox = self.sandbox_globals.copy()
        sandbox.update({
            'msg_direction': msg_direction,
            'msg_type': msg_type,
            'raw_msg': raw_msg,
            'action': 'send',  # Default action
            'modified_msg': None,  # For modifications
            'drop_reason': None,  # Reason for dropping
        })
        
        # Execute code
        try:
            if function.timeout:
                # Execute with timeout using threading
                import threading
                import queue
                
                result_queue = queue.Queue()
                
                def execute():
                    try:
                        exec(compiled_code, sandbox)
                        # Call the process_message function if defined
                        if 'process_message' in sandbox:
                            result = sandbox['process_message'](
                                msg_direction, msg_type, raw_msg
                            )
                            result_queue.put(result)
                        else:
                            result_queue.put(sandbox.get('action', 'send'))
                    except Exception as e:
                        result_queue.put(f'error: {e}')
                
                thread = threading.Thread(target=execute)
                thread.daemon = True
                thread.start()
                thread.join(timeout=function.timeout)
                
                if thread.is_alive():
                    logger.error(f"Function execution timed out after {function.timeout}s")
                    return 'drop'
                
                if not result_queue.empty():
                    result = result_queue.get()
                    if isinstance(result, str) and result.startswith('error:'):
                        logger.error(f"Function execution error: {result}")
                        return 'drop'
                    return result
                else:
                    return sandbox.get('action', 'send')
            else:
                # Execute without timeout
                exec(compiled_code, sandbox)
                
                # Call the process_message function if defined
                if 'process_message' in sandbox:
                    return sandbox['process_message'](msg_direction, msg_type, raw_msg)
                else:
                    # Use the action variable set by the script
                    return sandbox.get('action', 'send')
                
        except Exception as e:
            logger.error(f"Error executing Python function: {e}")
            if self.config.get('debug', False):
                logger.error(traceback.format_exc())
            return 'drop'
    
    async def intercept(
        self,
        message: MCPMessage,
        session: ProxySession
    ) -> InterceptorAction:
        """
        Process message through Python function
        
        Args:
            message: Message to process
            session: Current session
            
        Returns:
            Action based on function result
        """
        if not self.function:
            return InterceptorAction(type=ActionType.ALLOW)
        
        self.executions += 1
        
        # Prepare message data in standard format
        msg_direction = message.direction.value
        msg_type = message.type.value
        raw_msg = json.dumps(message.to_dict())
        
        # Execute function
        try:
            result = self._execute_function(
                self.function,
                msg_direction,
                msg_type,
                raw_msg
            )
            
            # Process result
            if result == 'send' or result == 'allow':
                self.successes += 1
                return InterceptorAction(
                    type=ActionType.ALLOW,
                    metadata={'python_function': 'allowed'}
                )
            
            elif result == 'drop' or result == 'block':
                self.failures += 1
                reason = self.sandbox_globals.get('drop_reason', 'Blocked by Python function')
                
                return InterceptorAction(
                    type=ActionType.BLOCK,
                    reason=reason,
                    metadata={'python_function': 'blocked', 'reason': reason}
                )
            
            elif result == 'modify' or result == 'transform':
                # Check for modified message
                modified_msg = self.sandbox_globals.get('modified_msg')
                
                if modified_msg:
                    try:
                        # Parse modified message
                        if isinstance(modified_msg, str):
                            modified_data = json.loads(modified_msg)
                        else:
                            modified_data = modified_msg
                        
                        # Create new message
                        new_message = MCPMessage.from_dict(
                            modified_data,
                            message.direction
                        )
                        
                        self.successes += 1
                        return InterceptorAction(
                            type=ActionType.TRANSFORM,
                            message=new_message,
                            reason="Modified by Python function",
                            metadata={'python_function': 'modified'}
                        )
                        
                    except Exception as e:
                        logger.error(f"Failed to parse modified message: {e}")
                        self.failures += 1
                        return InterceptorAction(type=ActionType.ALLOW)
                else:
                    # No modification provided
                    self.successes += 1
                    return InterceptorAction(type=ActionType.ALLOW)
            
            elif result == 'review' or result == 'approve':
                # Request human review
                return InterceptorAction(
                    type=ActionType.REVIEW,
                    reason="Python function requested review",
                    metadata={'python_function': 'review_requested'}
                )
            
            else:
                # Unknown result, default to allow
                logger.warning(f"Unknown function result: {result}")
                return InterceptorAction(type=ActionType.ALLOW)
                
        except Exception as e:
            logger.error(f"Error in Python function interceptor: {e}")
            self.failures += 1
            
            # Fail open or closed based on configuration
            if self.config.get('fail_closed', False):
                return InterceptorAction(
                    type=ActionType.BLOCK,
                    reason=f"Python function error: {e}"
                )
            else:
                return InterceptorAction(type=ActionType.ALLOW)
    
    def reload_function(self):
        """Reload the Python function (useful for development)"""
        self.function = self._load_function()
        self.compiled_cache.clear()
        logger.info("Python function reloaded")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get execution statistics"""
        return {
            'executions': self.executions,
            'successes': self.successes,
            'failures': self.failures,
            'success_rate': (self.successes / self.executions * 100) if self.executions > 0 else 0,
            'function_source': self.function.source if self.function else 'none',
            'safe_mode': self.safe_mode,
            'cached_functions': len(self.compiled_cache)
        }


# Example functions that users can use

EXAMPLE_FUNCTIONS = {
    'block_sensitive_tools': """
def process_message(msg_direction, msg_type, raw_msg):
    '''Block sensitive tool calls'''
    import json
    
    if msg_direction == 'outbound' and msg_type == 'request':
        msg = json.loads(raw_msg)
        if msg.get('method') == 'tools/call':
            tool = msg.get('params', {}).get('tool', '')
            if tool in ['rm', 'delete', 'format', 'exec']:
                global drop_reason
                drop_reason = f"Sensitive tool blocked: {tool}"
                return 'drop'
    
    return 'send'
""",
    
    'redact_secrets': """
def process_message(msg_direction, msg_type, raw_msg):
    '''Redact secrets from messages'''
    import json
    import re
    
    # Pattern for common secrets
    secret_pattern = r'(api_key|password|token|secret)\\s*[=:]\\s*["\']?([^"\'\\s]+)'
    
    msg = json.loads(raw_msg)
    msg_str = json.dumps(msg)
    
    if re.search(secret_pattern, msg_str, re.IGNORECASE):
        # Redact secrets
        modified_str = re.sub(
            secret_pattern,
            r'\\1=***REDACTED***',
            msg_str,
            flags=re.IGNORECASE
        )
        global modified_msg
        modified_msg = modified_str
        return 'modify'
    
    return 'send'
""",
    
    'rate_limit_simple': """
# Simple rate limiting
from datetime import datetime

if not hasattr(process_message, 'call_times'):
    process_message.call_times = []

def process_message(msg_direction, msg_type, raw_msg):
    '''Simple rate limiting'''
    import json
    
    if msg_direction == 'outbound' and msg_type == 'request':
        now = datetime.now()
        
        # Clean old entries (older than 1 minute)
        process_message.call_times = [
            t for t in process_message.call_times
            if (now - t).seconds < 60
        ]
        
        # Check rate limit (10 per minute)
        if len(process_message.call_times) >= 10:
            global drop_reason
            drop_reason = "Rate limit exceeded: 10 requests per minute"
            return 'drop'
        
        process_message.call_times.append(now)
    
    return 'send'
""",
    
    'custom_filter': """
def process_message(msg_direction, msg_type, raw_msg):
    '''Custom filtering logic'''
    import json
    
    msg = json.loads(raw_msg)
    
    # Block specific patterns
    if msg_direction == 'outbound':
        method = msg.get('method', '')
        
        # Block file operations on system directories
        if 'resources/write' in method:
            path = msg.get('params', {}).get('path', '')
            if path.startswith('/etc/') or path.startswith('/sys/'):
                global drop_reason
                drop_reason = f"System file write blocked: {path}"
                return 'drop'
        
        # Require review for database operations
        if 'database' in method.lower():
            return 'review'
    
    # Log and allow everything else
    log(f"Allowing {msg_direction} {msg_type}: {method}")
    return 'send'
"""
}