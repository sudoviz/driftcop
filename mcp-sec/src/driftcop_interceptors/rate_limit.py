"""
Rate limiting interceptor to prevent resource exhaustion
DriftCop's advanced rate limiting for DoS prevention
"""

import time
import asyncio
from collections import defaultdict, deque
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass
import logging

from .base import MessageInterceptor, InterceptorAction, ActionType
from ..driftcop_proxy.message import MCPMessage, MessageType, create_error_response
from ..driftcop_proxy.session import ProxySession

logger = logging.getLogger(__name__)


@dataclass
class RateLimit:
    """Rate limit configuration"""
    max_calls: int
    window_seconds: float
    
    def allows(self, request_count: int, window_start: float, now: float) -> bool:
        """Check if request is allowed under rate limit"""
        if now - window_start > self.window_seconds:
            # Window has expired, allow request
            return True
        return request_count < self.max_calls


class RateLimitInterceptor(MessageInterceptor):
    """
    Rate limiting interceptor to prevent DoS and resource exhaustion
    Implements token bucket algorithm with sliding window
    """
    
    name = "rate_limit"
    is_stateless = False  # Stateful due to rate tracking
    priority = 25  # Very high priority to block early
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        
        # Parse rate limits from config
        self.limits = self._parse_limits(config.get('limits', {}))
        
        # Rate tracking per session
        self.session_counters = defaultdict(lambda: defaultdict(lambda: deque(maxlen=1000)))
        
        # Global rate limits (across all sessions)
        self.global_counters = defaultdict(lambda: deque(maxlen=10000))
        
        # Configuration
        self.use_global_limits = config.get('use_global_limits', False)
        self.burst_multiplier = config.get('burst_multiplier', 1.5)
        self.enforce_mode = config.get('enforce_mode', 'block')  # block, delay, log
        
    def _parse_limits(self, limits_config: Dict[str, Any]) -> Dict[str, RateLimit]:
        """Parse rate limit configuration"""
        parsed_limits = {}
        
        for method, limit_spec in limits_config.items():
            if isinstance(limit_spec, dict):
                parsed_limits[method] = RateLimit(
                    max_calls=limit_spec.get('max_calls', 10),
                    window_seconds=limit_spec.get('window_seconds', 60)
                )
            elif isinstance(limit_spec, str):
                # Parse "10/minute" format
                parts = limit_spec.split('/')
                if len(parts) == 2:
                    max_calls = int(parts[0])
                    
                    # Parse time unit
                    time_unit = parts[1].lower()
                    if 'second' in time_unit:
                        window_seconds = 1
                    elif 'minute' in time_unit:
                        window_seconds = 60
                    elif 'hour' in time_unit:
                        window_seconds = 3600
                    else:
                        window_seconds = 60  # Default to minute
                    
                    parsed_limits[method] = RateLimit(
                        max_calls=max_calls,
                        window_seconds=window_seconds
                    )
        
        # Add default limits if none specified
        if not parsed_limits:
            parsed_limits = {
                'tools/call': RateLimit(max_calls=10, window_seconds=60),
                'resources/write': RateLimit(max_calls=5, window_seconds=60),
                'resources/delete': RateLimit(max_calls=2, window_seconds=300),
                'prompts/execute': RateLimit(max_calls=5, window_seconds=60)
            }
        
        return parsed_limits
    
    def should_process(self, message: MCPMessage) -> bool:
        """Check if message should be rate limited"""
        # Only rate limit requests
        return message.type == MessageType.REQUEST and message.method is not None
    
    async def intercept(
        self,
        message: MCPMessage,
        session: ProxySession
    ) -> InterceptorAction:
        """
        Apply rate limiting to message
        
        Args:
            message: Message to check
            session: Current session
            
        Returns:
            Action based on rate limit
        """
        if not self.should_process(message):
            return InterceptorAction(type=ActionType.ALLOW)
        
        method = message.method
        
        # Check if method has rate limit
        if method not in self.limits:
            # Check for wildcard limits
            for pattern, limit in self.limits.items():
                if '*' in pattern:
                    import fnmatch
                    if fnmatch.fnmatch(method, pattern):
                        break
            else:
                # No limit for this method
                return InterceptorAction(type=ActionType.ALLOW)
        else:
            limit = self.limits[method]
        
        now = time.time()
        
        # Check session-specific rate limit
        session_allowed = self._check_rate_limit(
            self.session_counters[session.id][method],
            limit,
            now
        )
        
        # Check global rate limit if enabled
        global_allowed = True
        if self.use_global_limits:
            global_allowed = self._check_rate_limit(
                self.global_counters[method],
                limit,
                now
            )
        
        # Determine if request is allowed
        allowed = session_allowed and global_allowed
        
        if allowed:
            # Record the request
            self.session_counters[session.id][method].append(now)
            if self.use_global_limits:
                self.global_counters[method].append(now)
            
            return InterceptorAction(type=ActionType.ALLOW)
        
        # Handle rate limit exceeded
        return await self._handle_rate_limit_exceeded(message, session, limit)
    
    def _check_rate_limit(
        self,
        timestamps: deque,
        limit: RateLimit,
        now: float
    ) -> bool:
        """
        Check if request is within rate limit
        
        Args:
            timestamps: Deque of request timestamps
            limit: Rate limit configuration
            now: Current timestamp
            
        Returns:
            True if request is allowed
        """
        # Remove old timestamps outside window
        cutoff = now - limit.window_seconds
        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()
        
        # Check if under limit
        return len(timestamps) < limit.max_calls
    
    async def _handle_rate_limit_exceeded(
        self,
        message: MCPMessage,
        session: ProxySession,
        limit: RateLimit
    ) -> InterceptorAction:
        """Handle rate limit exceeded based on enforcement mode"""
        
        reason = f"Rate limit exceeded for {message.method}: {limit.max_calls} calls per {limit.window_seconds}s"
        
        if self.enforce_mode == 'block':
            # Block the request
            logger.warning(f"Rate limit blocked: {reason}")
            
            # Update session stats
            session.messages_blocked += 1
            
            # Return error response
            return InterceptorAction(
                type=ActionType.RETURN,
                response=create_error_response(
                    message,
                    -32429,  # Too Many Requests
                    f"Rate limit exceeded: Please retry after {limit.window_seconds} seconds"
                ),
                reason=reason,
                metadata={'rate_limited': True}
            )
        
        elif self.enforce_mode == 'delay':
            # Delay the request (throttle)
            delay = self._calculate_delay(limit)
            logger.info(f"Rate limit delaying request by {delay:.2f}s: {message.method}")
            
            await asyncio.sleep(delay)
            
            return InterceptorAction(
                type=ActionType.ALLOW,
                metadata={'rate_limited': True, 'delayed': delay}
            )
        
        else:  # 'log' mode
            # Just log but allow
            logger.warning(f"Rate limit exceeded (log only): {reason}")
            
            return InterceptorAction(
                type=ActionType.ALLOW,
                metadata={'rate_limited': True, 'logged_only': True}
            )
    
    def _calculate_delay(self, limit: RateLimit) -> float:
        """Calculate delay for throttling"""
        # Simple exponential backoff
        base_delay = limit.window_seconds / limit.max_calls
        return min(base_delay * 2, 10.0)  # Max 10 second delay
    
    def get_usage_stats(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Get rate limit usage statistics"""
        now = time.time()
        stats = {}
        
        if session_id:
            # Session-specific stats
            counters = self.session_counters.get(session_id, {})
            for method, timestamps in counters.items():
                if method in self.limits:
                    limit = self.limits[method]
                    cutoff = now - limit.window_seconds
                    recent_count = sum(1 for t in timestamps if t > cutoff)
                    stats[method] = {
                        'current': recent_count,
                        'limit': limit.max_calls,
                        'window': limit.window_seconds,
                        'usage_percent': (recent_count / limit.max_calls) * 100
                    }
        else:
            # Global stats
            for method, timestamps in self.global_counters.items():
                if method in self.limits:
                    limit = self.limits[method]
                    cutoff = now - limit.window_seconds
                    recent_count = sum(1 for t in timestamps if t > cutoff)
                    stats[method] = {
                        'current': recent_count,
                        'limit': limit.max_calls,
                        'window': limit.window_seconds,
                        'usage_percent': (recent_count / limit.max_calls) * 100
                    }
        
        return stats
    
    def reset_limits(self, session_id: Optional[str] = None, method: Optional[str] = None):
        """Reset rate limit counters"""
        if session_id and method:
            # Reset specific method for session
            if session_id in self.session_counters:
                self.session_counters[session_id][method].clear()
        elif session_id:
            # Reset all methods for session
            if session_id in self.session_counters:
                self.session_counters[session_id].clear()
        elif method:
            # Reset specific method globally
            self.global_counters[method].clear()
        else:
            # Reset everything
            self.session_counters.clear()
            self.global_counters.clear()