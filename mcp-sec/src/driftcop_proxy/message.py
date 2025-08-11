"""
MCP message parsing and handling with optimization
"""

import json
import hashlib
import re
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Union
from functools import lru_cache
import orjson

class MessageType(Enum):
    """MCP message types"""
    REQUEST = "request"
    RESPONSE_SUCCESS = "response_success"
    RESPONSE_FAILURE = "response_failure"
    NOTIFICATION = "notification"
    UNKNOWN = "unknown"

class MessageDirection(Enum):
    """Message direction"""
    INBOUND = "inbound"
    OUTBOUND = "outbound"

# Pre-compiled patterns for fast parsing
PATTERNS = {
    'method': re.compile(rb'"method"\s*:\s*"([^"]+)"'),
    'result': re.compile(rb'"result"\s*:'),
    'error': re.compile(rb'"error"\s*:'),
    'id': re.compile(rb'"id"\s*:\s*([^,}]+)'),
    'jsonrpc': re.compile(rb'"jsonrpc"\s*:\s*"2\.0"')
}

# Safe methods that don't need deep inspection
SAFE_METHODS = frozenset([
    'initialize',
    'initialized', 
    'ping',
    'pong',
    'tools/list',
    'prompts/list',
    'resources/list',
    'logging/setLevel',
    'completion/complete'
])

# Sensitive methods that need extra scrutiny
SENSITIVE_METHODS = frozenset([
    'tools/call',
    'resources/write',
    'resources/delete',
    'prompts/execute',
    'sampling/createMessage'
])

@dataclass
class MCPMessage:
    """
    Optimized MCP message with lazy parsing and caching
    """
    type: MessageType
    direction: MessageDirection
    _raw_data: bytes = field(repr=False)
    _parsed: Optional[Dict] = field(default=None, init=False, repr=False)
    _hash: Optional[str] = field(default=None, init=False, repr=False)
    _id: Optional[Union[str, int]] = field(default=None, init=False)
    
    @property
    def parsed(self) -> Dict:
        """Lazy parse on first access"""
        if self._parsed is None:
            try:
                self._parsed = orjson.loads(self._raw_data)
            except:
                # Fallback to standard json
                self._parsed = json.loads(self._raw_data)
        return self._parsed
    
    @property
    def method(self) -> Optional[str]:
        """Extract method name"""
        if self.type == MessageType.REQUEST:
            return self.parsed.get('method')
        return None
    
    @property
    def params(self) -> Optional[Dict]:
        """Extract parameters"""
        if self.type == MessageType.REQUEST:
            return self.parsed.get('params', {})
        return None
    
    @property
    def result(self) -> Optional[Any]:
        """Extract result"""
        if self.type == MessageType.RESPONSE_SUCCESS:
            return self.parsed.get('result')
        return None
    
    @property
    def error(self) -> Optional[Dict]:
        """Extract error"""
        if self.type == MessageType.RESPONSE_FAILURE:
            return self.parsed.get('error')
        return None
    
    @property
    def id(self) -> Optional[Union[str, int]]:
        """Extract message ID"""
        if self._id is None:
            self._id = self.parsed.get('id')
        return self._id
    
    @property
    def hash(self) -> str:
        """Calculate message hash for deduplication"""
        if self._hash is None:
            self._hash = hashlib.blake2b(self._raw_data, digest_size=16).hexdigest()
        return self._hash
    
    @lru_cache(maxsize=1)
    def is_safe(self) -> bool:
        """Check if message is safe (cached)"""
        return self.method in SAFE_METHODS
    
    @lru_cache(maxsize=1)
    def is_sensitive(self) -> bool:
        """Check if message contains sensitive operations (cached)"""
        return self.method in SENSITIVE_METHODS
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return self.parsed
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        if self._parsed is None:
            # Return raw data if not parsed
            return self._raw_data.decode('utf-8')
        return orjson.dumps(self._parsed).decode('utf-8')
    
    def to_bytes(self) -> bytes:
        """Get raw bytes"""
        if self._parsed is None:
            return self._raw_data
        return orjson.dumps(self._parsed)
    
    @classmethod
    def from_dict(cls, data: Dict, direction: MessageDirection) -> 'MCPMessage':
        """Create message from dictionary"""
        # Determine type
        if 'method' in data:
            msg_type = MessageType.REQUEST
        elif 'result' in data:
            msg_type = MessageType.RESPONSE_SUCCESS
        elif 'error' in data:
            msg_type = MessageType.RESPONSE_FAILURE
        else:
            msg_type = MessageType.NOTIFICATION
        
        # Create message
        msg = cls(
            type=msg_type,
            direction=direction,
            _raw_data=orjson.dumps(data)
        )
        msg._parsed = data
        return msg
    
    def clone(self) -> 'MCPMessage':
        """Create a copy of the message"""
        return MCPMessage(
            type=self.type,
            direction=self.direction,
            _raw_data=self._raw_data
        )
    
    def with_modifications(self, **kwargs) -> 'MCPMessage':
        """Create modified copy of message"""
        data = self.parsed.copy()
        data.update(kwargs)
        return self.from_dict(data, self.direction)


class MessageParser:
    """
    High-performance message parser with caching
    """
    
    def __init__(self, cache_size: int = 1000):
        self.cache = {}  # Simple dict cache
        self.cache_size = cache_size
        
    def parse(self, data: bytes, direction: MessageDirection) -> MCPMessage:
        """
        Parse message from bytes
        
        Args:
            data: Raw message bytes
            direction: Message direction
            
        Returns:
            Parsed MCPMessage
        """
        # Strip whitespace
        data = data.strip()
        if not data:
            raise ValueError("Empty message")
        
        # Check cache
        msg_hash = hashlib.blake2b(data, digest_size=8).digest()
        cache_key = (msg_hash, direction)
        
        if cache_key in self.cache:
            return self.cache[cache_key].clone()
        
        # Fast type detection using regex
        msg_type = self._detect_type_fast(data)
        
        # Create message with lazy parsing
        message = MCPMessage(
            type=msg_type,
            direction=direction,
            _raw_data=data
        )
        
        # Cache if room
        if len(self.cache) < self.cache_size:
            self.cache[cache_key] = message
        
        return message
    
    def _detect_type_fast(self, data: bytes) -> MessageType:
        """
        Fast message type detection without full JSON parse
        
        Args:
            data: Raw message bytes
            
        Returns:
            Detected message type
        """
        # Check for JSON-RPC 2.0
        if not PATTERNS['jsonrpc'].search(data):
            return MessageType.UNKNOWN
        
        # Check for request (has method)
        if PATTERNS['method'].search(data):
            return MessageType.REQUEST
        
        # Check for response (has result or error)
        if PATTERNS['result'].search(data):
            return MessageType.RESPONSE_SUCCESS
        
        if PATTERNS['error'].search(data):
            return MessageType.RESPONSE_FAILURE
        
        # Check if it has an ID (could be notification if no ID)
        if not PATTERNS['id'].search(data):
            return MessageType.NOTIFICATION
        
        return MessageType.UNKNOWN
    
    def parse_batch(self, messages: list[bytes], direction: MessageDirection) -> list[MCPMessage]:
        """
        Parse multiple messages efficiently
        
        Args:
            messages: List of raw message bytes
            direction: Message direction
            
        Returns:
            List of parsed messages
        """
        return [self.parse(msg, direction) for msg in messages]


class RequestCache:
    """
    Cache for correlating requests with responses
    """
    
    def __init__(self, max_size: int = 10000, ttl: int = 300):
        """
        Initialize request cache
        
        Args:
            max_size: Maximum cache size
            ttl: Time-to-live in seconds
        """
        self.cache = {}
        self.max_size = max_size
        self.ttl = ttl
        self.access_times = {}
        
    def store_request(self, message: MCPMessage):
        """Store request for correlation"""
        if message.type != MessageType.REQUEST or not message.id:
            return
        
        # Evict old entries if needed
        if len(self.cache) >= self.max_size:
            self._evict_oldest()
        
        self.cache[message.id] = message
        self.access_times[message.id] = time.time()
    
    def get_request(self, msg_id: Union[str, int]) -> Optional[MCPMessage]:
        """Get cached request by ID"""
        return self.cache.get(msg_id)
    
    def remove_request(self, msg_id: Union[str, int]):
        """Remove request from cache"""
        self.cache.pop(msg_id, None)
        self.access_times.pop(msg_id, None)
    
    def _evict_oldest(self):
        """Evict oldest entry from cache"""
        if not self.access_times:
            return
        
        oldest_id = min(self.access_times, key=self.access_times.get)
        self.remove_request(oldest_id)
    
    def cleanup_expired(self):
        """Remove expired entries"""
        now = time.time()
        expired = [
            msg_id for msg_id, access_time in self.access_times.items()
            if now - access_time > self.ttl
        ]
        for msg_id in expired:
            self.remove_request(msg_id)


import time

def create_error_response(request: MCPMessage, code: int, message: str) -> MCPMessage:
    """
    Create error response for a request
    
    Args:
        request: Original request message
        code: Error code
        message: Error message
        
    Returns:
        Error response message
    """
    response_data = {
        "jsonrpc": "2.0",
        "id": request.id,
        "error": {
            "code": code,
            "message": message
        }
    }
    
    return MCPMessage.from_dict(response_data, MessageDirection.INBOUND)


def create_success_response(request: MCPMessage, result: Any) -> MCPMessage:
    """
    Create success response for a request
    
    Args:
        request: Original request message
        result: Result data
        
    Returns:
        Success response message
    """
    response_data = {
        "jsonrpc": "2.0",
        "id": request.id,
        "result": result
    }
    
    return MCPMessage.from_dict(response_data, MessageDirection.INBOUND)