"""
Factory for creating interceptors from configuration
"""

import logging
from typing import Dict, Any, Optional

from .base import MessageInterceptor
from .security import SecurityInterceptor, SigstoreInterceptor
from .filter import FilterInterceptor
from .approval import ApprovalInterceptor
from .rate_limit import RateLimitInterceptor
from .chain import InterceptorChain
from .logging import LoggingInterceptor
from .audit import AuditInterceptor
from .transform import TransformInterceptor
from .python_function import PythonFunctionInterceptor

logger = logging.getLogger(__name__)


class InterceptorFactory:
    """
    Factory for creating interceptors from configuration
    """
    
    def __init__(self):
        # Registry of interceptor types
        self.registry = {
            'security': SecurityInterceptor,
            'sigstore': SigstoreInterceptor,
            'filter': FilterInterceptor,
            'approval': ApprovalInterceptor,
            'rate_limit': RateLimitInterceptor,
            'ratelimit': RateLimitInterceptor,  # Alias
            'chain': self._create_chain,
            'logging': LoggingInterceptor,
            'audit': AuditInterceptor,
            'transform': TransformInterceptor,
            'python_function': PythonFunctionInterceptor,
            'pyfunc': PythonFunctionInterceptor,  # Alias for compatibility
        }
    
    def create(self, config: Dict[str, Any]) -> Optional[MessageInterceptor]:
        """
        Create interceptor from configuration
        
        Args:
            config: Interceptor configuration with 'type' field
            
        Returns:
            Interceptor instance or None
        """
        interceptor_type = config.get('type')
        if not interceptor_type:
            logger.error("Interceptor configuration missing 'type' field")
            return None
        
        interceptor_type = interceptor_type.lower()
        
        if interceptor_type not in self.registry:
            logger.error(f"Unknown interceptor type: {interceptor_type}")
            return None
        
        try:
            # Get interceptor class or factory function
            factory = self.registry[interceptor_type]
            
            # Check if it's a class or function
            if callable(factory) and not isinstance(factory, type):
                # It's a factory function
                return factory(config.get('config', {}))
            else:
                # It's a class
                return factory(config.get('config', {}))
                
        except Exception as e:
            logger.error(f"Error creating interceptor {interceptor_type}: {e}")
            return None
    
    def _create_chain(self, config: Dict[str, Any]) -> Optional[InterceptorChain]:
        """Create chain interceptor"""
        chain_configs = config.get('chain', [])
        interceptors = []
        
        for interceptor_config in chain_configs:
            interceptor = self.create(interceptor_config)
            if interceptor:
                interceptors.append(interceptor)
        
        if not interceptors:
            logger.warning("Chain interceptor created with no sub-interceptors")
            return None
        
        return InterceptorChain(interceptors)
    
    
    def register(self, name: str, interceptor_class: type):
        """
        Register custom interceptor type
        
        Args:
            name: Name for the interceptor type
            interceptor_class: Interceptor class
        """
        self.registry[name.lower()] = interceptor_class
        logger.info(f"Registered interceptor type: {name}")