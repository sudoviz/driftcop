"""
Logging interceptor for audit and debugging
"""

import json
import logging
import sys
from pathlib import Path
from typing import Dict, Any, Optional, TextIO
from datetime import datetime
from logging.handlers import RotatingFileHandler, SysLogHandler
import hashlib

from .base import MessageInterceptor, InterceptorAction, ActionType
from ..driftcop_proxy.message import MCPMessage
from ..driftcop_proxy.session import ProxySession

logger = logging.getLogger(__name__)


class LoggingInterceptor(MessageInterceptor):
    """
    Comprehensive logging interceptor for messages
    Supports multiple outputs and formats
    """
    
    name = "logging"
    priority = 1  # Very low priority - runs last
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        
        # Logging configuration
        self.log_level = getattr(logging, config.get('log_level', 'INFO').upper())
        self.include_payload = config.get('include_payload', True)
        self.include_metadata = config.get('include_metadata', False)
        self.include_stack_trace = config.get('include_stack_trace', False)
        self.sanitize_sensitive = config.get('sanitize_sensitive', True)
        
        # Output configuration
        self.output = config.get('output', 'console')
        self.outputs = config.get('outputs', [self.output])
        self.format = config.get('format', 'json')  # json, pretty, compact
        self.colorize = config.get('colorize', False)
        
        # File output
        self.file_path = None
        self.file_handler = None
        if 'file' in self.outputs or self.output == 'file':
            file_path_str = config.get('file_path', '~/.driftcop/logs/messages.log')
            self.file_path = Path(file_path_str).expanduser()
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Setup rotation
            rotation = config.get('rotation', {})
            if rotation.get('enabled', True):
                max_bytes = self._parse_size(rotation.get('max_size', '100MB'))
                backup_count = rotation.get('max_files', 10)
                self.file_handler = RotatingFileHandler(
                    self.file_path,
                    maxBytes=max_bytes,
                    backupCount=backup_count
                )
            else:
                self.file_handler = logging.FileHandler(self.file_path)
        
        # Syslog output
        self.syslog_handler = None
        if 'syslog' in self.outputs:
            syslog_config = config.get('syslog', {})
            address = (
                syslog_config.get('host', 'localhost'),
                syslog_config.get('port', 514)
            )
            facility = getattr(
                SysLogHandler,
                f"LOG_{syslog_config.get('facility', 'LOCAL0').upper()}"
            )
            socktype = (
                socket.SOCK_STREAM
                if syslog_config.get('protocol', 'udp').lower() == 'tcp'
                else socket.SOCK_DGRAM
            )
            self.syslog_handler = SysLogHandler(
                address=address,
                facility=facility,
                socktype=socktype
            )
        
        # Setup custom logger
        self.message_logger = logging.getLogger('driftcop.messages')
        self.message_logger.setLevel(self.log_level)
        
        # Clear existing handlers
        self.message_logger.handlers.clear()
        
        # Add handlers
        if 'console' in self.outputs or self.output == 'console':
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(self.log_level)
            self.message_logger.addHandler(console_handler)
        
        if self.file_handler:
            self.file_handler.setLevel(self.log_level)
            self.message_logger.addHandler(self.file_handler)
        
        if self.syslog_handler:
            self.syslog_handler.setLevel(self.log_level)
            self.message_logger.addHandler(self.syslog_handler)
        
        # Message counter
        self.message_count = 0
        
        # Sensitive patterns for sanitization
        self.sensitive_patterns = [
            'password', 'token', 'secret', 'api_key', 'auth',
            'credential', 'private_key', 'access_token', 'refresh_token'
        ]
    
    def _parse_size(self, size_str: str) -> int:
        """Parse size string like '100MB' to bytes"""
        size_str = size_str.upper()
        if size_str.endswith('KB'):
            return int(size_str[:-2]) * 1024
        elif size_str.endswith('MB'):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith('GB'):
            return int(size_str[:-2]) * 1024 * 1024 * 1024
        else:
            return int(size_str)
    
    def _sanitize_data(self, data: Any) -> Any:
        """Sanitize sensitive data"""
        if not self.sanitize_sensitive:
            return data
        
        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                # Check if key contains sensitive pattern
                key_lower = key.lower()
                is_sensitive = any(pattern in key_lower for pattern in self.sensitive_patterns)
                
                if is_sensitive:
                    sanitized[key] = '***REDACTED***'
                elif isinstance(value, (dict, list)):
                    sanitized[key] = self._sanitize_data(value)
                else:
                    sanitized[key] = value
            return sanitized
        
        elif isinstance(data, list):
            return [self._sanitize_data(item) for item in data]
        
        return data
    
    def _format_message(self, log_entry: Dict[str, Any]) -> str:
        """Format log entry based on configured format"""
        if self.format == 'json':
            return json.dumps(log_entry, default=str)
        
        elif self.format == 'pretty':
            # Pretty printed format
            lines = []
            lines.append(f"[{log_entry['timestamp']}] {log_entry['level']} - {log_entry['event']}")
            lines.append(f"  Direction: {log_entry['direction']}")
            lines.append(f"  Type: {log_entry['message_type']}")
            if log_entry.get('method'):
                lines.append(f"  Method: {log_entry['method']}")
            if log_entry.get('session_id'):
                lines.append(f"  Session: {log_entry['session_id']}")
            if self.include_payload and log_entry.get('payload'):
                lines.append(f"  Payload: {json.dumps(log_entry['payload'], indent=4)}")
            if self.include_metadata and log_entry.get('metadata'):
                lines.append(f"  Metadata: {json.dumps(log_entry['metadata'], indent=4)}")
            
            result = '\n'.join(lines)
            
            # Add colors if enabled
            if self.colorize:
                # ANSI color codes
                colors = {
                    'ERROR': '\033[91m',  # Red
                    'WARNING': '\033[93m',  # Yellow
                    'INFO': '\033[92m',  # Green
                    'DEBUG': '\033[94m',  # Blue
                }
                reset = '\033[0m'
                
                level = log_entry['level']
                if level in colors:
                    result = colors[level] + result + reset
            
            return result
        
        elif self.format == 'compact':
            # Single line format
            parts = [
                log_entry['timestamp'],
                log_entry['level'],
                log_entry['event'],
                f"dir={log_entry['direction']}",
                f"type={log_entry['message_type']}"
            ]
            if log_entry.get('method'):
                parts.append(f"method={log_entry['method']}")
            if log_entry.get('session_id'):
                parts.append(f"session={log_entry['session_id'][:8]}")
            
            return ' | '.join(parts)
        
        return str(log_entry)
    
    async def intercept(
        self,
        message: MCPMessage,
        session: ProxySession
    ) -> InterceptorAction:
        """
        Log message
        
        Args:
            message: Message to log
            session: Current session
            
        Returns:
            Always returns ALLOW action
        """
        self.message_count += 1
        
        # Prepare log entry
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'level': logging.getLevelName(self.log_level),
            'event': 'message_intercepted',
            'message_id': message.id,
            'direction': message.direction.value,
            'message_type': message.type.value,
            'method': message.method,
            'session_id': session.id,
            'client': session.client_name,
            'message_number': self.message_count
        }
        
        # Add payload if configured
        if self.include_payload:
            payload = message.to_dict()
            log_entry['payload'] = self._sanitize_data(payload)
            
            # Add hash for integrity
            if self.config.get('hash_messages', False):
                payload_str = json.dumps(payload, sort_keys=True)
                log_entry['hash'] = hashlib.sha256(payload_str.encode()).hexdigest()
        
        # Add metadata if configured
        if self.include_metadata:
            log_entry['metadata'] = {
                'risk_score': session.security_context.current_risk,
                'violations': len(session.security_context.violations),
                'messages_processed': session.messages_processed,
                'messages_blocked': session.messages_blocked,
                'messages_transformed': session.messages_transformed
            }
        
        # Add stack trace if error
        if self.include_stack_trace and message.error:
            import traceback
            log_entry['stack_trace'] = traceback.format_stack()
        
        # Format and log the message
        formatted_message = self._format_message(log_entry)
        
        # Log at appropriate level
        if message.error:
            self.message_logger.error(formatted_message)
        elif session.security_context.current_risk > 5.0:
            self.message_logger.warning(formatted_message)
        else:
            self.message_logger.info(formatted_message)
        
        # Always allow - logging doesn't block
        return InterceptorAction(
            type=ActionType.ALLOW,
            metadata={'logged': True, 'log_entry_id': self.message_count}
        )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get logging statistics"""
        stats = {
            'messages_logged': self.message_count,
            'log_level': logging.getLevelName(self.log_level),
            'outputs': self.outputs,
            'format': self.format
        }
        
        if self.file_path:
            stats['log_file'] = str(self.file_path)
            if self.file_path.exists():
                stats['log_file_size'] = self.file_path.stat().st_size
        
        return stats


# Import socket for syslog
import socket