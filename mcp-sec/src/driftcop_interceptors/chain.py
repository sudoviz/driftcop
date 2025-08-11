"""
Interceptor chain implementation for sequential processing
"""

import logging
import asyncio
from typing import List, Optional, Dict, Any
from dataclasses import dataclass

from .base import MessageInterceptor, InterceptorAction, ActionType
from ..driftcop_proxy.message import MCPMessage
from ..driftcop_proxy.session import ProxySession

logger = logging.getLogger(__name__)


class InterceptorChain:
    """
    Chain of interceptors that process messages sequentially
    Implements sequential interceptor processing with priority ordering
    """
    
    def __init__(self, interceptors: List[MessageInterceptor]):
        """
        Initialize interceptor chain
        
        Args:
            interceptors: List of interceptors to chain
        """
        # Sort by priority (higher priority first)
        self.interceptors = sorted(
            interceptors,
            key=lambda x: x.priority,
            reverse=True
        )
        
        # Separate stateless for potential parallel execution
        self.stateless_interceptors = [i for i in self.interceptors if i.is_stateless]
        self.stateful_interceptors = [i for i in self.interceptors if not i.is_stateless]
        
        logger.info(f"Initialized chain with {len(self.interceptors)} interceptors")
    
    async def process(
        self,
        message: MCPMessage,
        session: ProxySession
    ) -> InterceptorAction:
        """
        Process message through interceptor chain
        
        Args:
            message: Message to process
            session: Current session
            
        Returns:
            Final action from chain
        """
        current_message = message
        accumulated_metadata = {}
        
        # Process through all interceptors
        for interceptor in self.interceptors:
            try:
                # Check if interceptor should process this message
                if not interceptor.should_process(current_message):
                    logger.debug(f"Skipping {interceptor.name} for {current_message.method}")
                    continue
                
                # Process message
                action = await interceptor.process(current_message, session)
                
                # Accumulate metadata
                if action.metadata:
                    accumulated_metadata.update(action.metadata)
                
                # Handle action based on type
                if action.type == ActionType.BLOCK:
                    # Stop processing and block
                    logger.info(f"Chain blocked by {interceptor.name}: {action.reason}")
                    action.metadata = accumulated_metadata
                    return action
                
                elif action.type == ActionType.RETURN:
                    # Stop processing and return synthetic response
                    logger.info(f"Chain returning response from {interceptor.name}: {action.reason}")
                    action.metadata = accumulated_metadata
                    return action
                
                elif action.type == ActionType.QUEUE:
                    # Stop processing and queue for approval
                    logger.info(f"Chain queuing from {interceptor.name}: {action.reason}")
                    action.metadata = accumulated_metadata
                    return action
                
                elif action.type == ActionType.TRANSFORM:
                    # Transform message and continue
                    if action.message:
                        logger.debug(f"Message transformed by {interceptor.name}")
                        current_message = action.message
                    # Continue to next interceptor
                
                # ActionType.ALLOW - continue to next interceptor
                
            except Exception as e:
                logger.error(f"Error in interceptor {interceptor.name}: {e}")
                # Continue processing despite individual interceptor errors
                # Graceful degradation on interceptor failure
                continue
        
        # All interceptors passed - allow with possible transformation
        return InterceptorAction(
            type=ActionType.ALLOW,
            message=current_message if current_message != message else None,
            metadata=accumulated_metadata
        )
    
    async def process_parallel(
        self,
        message: MCPMessage,
        session: ProxySession
    ) -> InterceptorAction:
        """
        Process stateless interceptors in parallel for performance
        Only use when order doesn't matter
        
        Args:
            message: Message to process
            session: Current session
            
        Returns:
            Final action from chain
        """
        # Run stateless interceptors in parallel
        if self.stateless_interceptors:
            tasks = [
                interceptor.process(message, session)
                for interceptor in self.stateless_interceptors
                if interceptor.should_process(message)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Check for blocking actions
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"Error in parallel interceptor: {result}")
                    continue
                
                if result.type in (ActionType.BLOCK, ActionType.RETURN, ActionType.QUEUE):
                    return result
        
        # Process stateful interceptors sequentially
        current_message = message
        for interceptor in self.stateful_interceptors:
            if not interceptor.should_process(current_message):
                continue
            
            action = await interceptor.process(current_message, session)
            
            if action.type in (ActionType.BLOCK, ActionType.RETURN, ActionType.QUEUE):
                return action
            elif action.type == ActionType.TRANSFORM and action.message:
                current_message = action.message
        
        return InterceptorAction(
            type=ActionType.ALLOW,
            message=current_message if current_message != message else None
        )
    
    def add_interceptor(self, interceptor: MessageInterceptor):
        """
        Add interceptor to chain
        
        Args:
            interceptor: Interceptor to add
        """
        self.interceptors.append(interceptor)
        self.interceptors.sort(key=lambda x: x.priority, reverse=True)
        
        if interceptor.is_stateless:
            self.stateless_interceptors.append(interceptor)
            self.stateless_interceptors.sort(key=lambda x: x.priority, reverse=True)
        else:
            self.stateful_interceptors.append(interceptor)
            self.stateful_interceptors.sort(key=lambda x: x.priority, reverse=True)
    
    def remove_interceptor(self, name: str) -> bool:
        """
        Remove interceptor by name
        
        Args:
            name: Name of interceptor to remove
            
        Returns:
            True if removed
        """
        removed = False
        
        # Remove from main list
        self.interceptors = [i for i in self.interceptors if i.name != name]
        
        # Remove from categorized lists
        original_stateless = len(self.stateless_interceptors)
        self.stateless_interceptors = [i for i in self.stateless_interceptors if i.name != name]
        if len(self.stateless_interceptors) < original_stateless:
            removed = True
        
        original_stateful = len(self.stateful_interceptors)
        self.stateful_interceptors = [i for i in self.stateful_interceptors if i.name != name]
        if len(self.stateful_interceptors) < original_stateful:
            removed = True
        
        return removed
    
    def get_interceptor(self, name: str) -> Optional[MessageInterceptor]:
        """
        Get interceptor by name
        
        Args:
            name: Name of interceptor
            
        Returns:
            Interceptor instance or None
        """
        for interceptor in self.interceptors:
            if interceptor.name == name:
                return interceptor
        return None
    
    def list_interceptors(self) -> List[Dict[str, Any]]:
        """
        List all interceptors in chain
        
        Returns:
            List of interceptor info
        """
        return [
            {
                'name': i.name,
                'priority': i.priority,
                'stateless': i.is_stateless,
                'cpu_intensive': i.is_cpu_intensive,
                'enabled': i.enabled
            }
            for i in self.interceptors
        ]