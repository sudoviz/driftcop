"""
DriftCop Proxy - High-performance MCP security proxy
"""

from .core import DriftCopProxy
from .message import MCPMessage, MessageType, MessageDirection
from .session import SessionManager, ProxySession

__version__ = "1.0.0"

__all__ = [
    "DriftCopProxy",
    "MCPMessage",
    "MessageType",
    "MessageDirection",
    "SessionManager",
    "ProxySession",
]