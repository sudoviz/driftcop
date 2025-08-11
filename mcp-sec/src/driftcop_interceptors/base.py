"""
Base interceptor interface and action types
"""

from abc import ABC, abstractmethod
from enum import Enum
from dataclasses import dataclass
from typing import Optional, Any, Dict
import logging

from ..driftcop_proxy.message import MCPMessage
from ..driftcop_proxy.session import ProxySession

logger = logging.getLogger(__name__)


class ActionType(Enum):
    """Interceptor action types"""
    ALLOW = "allow"           # Forward message unchanged
    BLOCK = "block"           # Block message entirely
    TRANSFORM = "transform"   # Modify message before forwarding
    QUEUE = "queue"          # Queue for manual approval
    RETURN = "return"        # Return synthetic response


@dataclass
class InterceptorAction:
    """Result of interceptor processing"""
    type: ActionType
    message: Optional[MCPMessage] = None  # Modified message for TRANSFORM
    response: Optional[MCPMessage] = None  # Synthetic response for RETURN
    reason: Optional[str] = None  # Reason for action
    metadata: Dict[str, Any] = None  # Additional metadata
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
    
    def should_forward(self) -> bool:
        """Check if message should be forwarded"""
        return self.type in (ActionType.ALLOW, ActionType.TRANSFORM)
    
    def should_block(self) -> bool:
        """Check if message should be blocked"""
        return self.type == ActionType.BLOCK
    
    def should_return(self) -> bool:
        """Check if synthetic response should be returned"""
        return self.type == ActionType.RETURN
    
    def should_queue(self) -> bool:
        """Check if message should be queued for approval"""
        return self.type == ActionType.QUEUE
    
    def get_message(self) -> MCPMessage:
        """Get message to forward"""
        if self.type == ActionType.TRANSFORM and self.message:
            return self.message
        return None
    
    def get_response(self) -> MCPMessage:
        """Get synthetic response"""
        return self.response


class MessageInterceptor(ABC):
    """
    Base class for all message interceptors
    """
    
    # Optimization hints
    is_stateless: bool = True  # Can be run in parallel
    is_cpu_intensive: bool = False  # Should run in process pool
    priority: int = 0  # Higher priority runs first
    name: str = "base"  # Interceptor name
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize interceptor
        
        Args:
            config: Interceptor configuration
        """
        self.config = config or {}
        self.enabled = self.config.get('enabled', True)
    
    @abstractmethod
    async def intercept(
        self,
        message: MCPMessage,
        session: ProxySession
    ) -> InterceptorAction:
        """
        Process message and return action
        
        Args:
            message: Message to process
            session: Current proxy session
            
        Returns:
            Action to take
        """
        pass
    
    async def process(
        self,
        message: MCPMessage,
        session: ProxySession
    ) -> InterceptorAction:
        """
        Process message with error handling
        
        Args:
            message: Message to process
            session: Current proxy session
            
        Returns:
            Action to take
        """
        if not self.enabled:
            return InterceptorAction(type=ActionType.ALLOW)
        
        try:
            action = await self.intercept(message, session)
            
            # Log action if significant
            if action.type != ActionType.ALLOW:
                logger.info(
                    f"{self.name} interceptor: {action.type.value} "
                    f"for {message.method} - {action.reason}"
                )
            
            return action
            
        except Exception as e:
            logger.error(f"Error in {self.name} interceptor: {e}")
            # On error, default to allow to avoid breaking the proxy
            return InterceptorAction(
                type=ActionType.ALLOW,
                metadata={'error': str(e)}
            )
    
    def should_process(self, message: MCPMessage) -> bool:
        """
        Check if interceptor should process this message
        
        Args:
            message: Message to check
            
        Returns:
            True if should process
        """
        # Can be overridden for optimization
        return True


class CachedInterceptor(MessageInterceptor):
    """
    Base class for interceptors with result caching
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.cache = {}
        self.cache_size = self.config.get('cache_size', 1000)
    
    async def intercept(
        self,
        message: MCPMessage,
        session: ProxySession
    ) -> InterceptorAction:
        """Process with caching"""
        # Generate cache key
        cache_key = self._get_cache_key(message, session)
        
        # Check cache
        if cache_key in self.cache:
            logger.debug(f"{self.name} cache hit for {cache_key}")
            return self.cache[cache_key]
        
        # Process message
        action = await self._intercept_impl(message, session)
        
        # Cache result if there's room
        if len(self.cache) < self.cache_size:
            self.cache[cache_key] = action
        
        return action
    
    def _get_cache_key(self, message: MCPMessage, session: ProxySession) -> str:
        """Generate cache key for message"""
        return f"{message.hash}:{session.id}"
    
    @abstractmethod
    async def _intercept_impl(
        self,
        message: MCPMessage,
        session: ProxySession
    ) -> InterceptorAction:
        """Actual interception logic"""
        pass


class CompositeInterceptor(MessageInterceptor):
    """
    Base class for interceptors that combine multiple sub-interceptors
    """
    
    def __init__(
        self,
        interceptors: list[MessageInterceptor],
        config: Optional[Dict[str, Any]] = None
    ):
        super().__init__(config)
        self.interceptors = interceptors
        self.is_stateless = all(i.is_stateless for i in interceptors)
        self.is_cpu_intensive = any(i.is_cpu_intensive for i in interceptors)
    
    async def intercept(
        self,
        message: MCPMessage,
        session: ProxySession
    ) -> InterceptorAction:
        """Process through all sub-interceptors"""
        for interceptor in self.interceptors:
            action = await interceptor.process(message, session)
            
            # Stop on blocking actions
            if action.type in (ActionType.BLOCK, ActionType.RETURN, ActionType.QUEUE):
                return action
            
            # Update message for transform
            if action.type == ActionType.TRANSFORM and action.message:
                message = action.message
        
        return InterceptorAction(type=ActionType.ALLOW, message=message)