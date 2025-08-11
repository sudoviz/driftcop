"""
Filter interceptor with complex boolean logic for message filtering
"""

import logging
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass
from enum import Enum

from .base import MessageInterceptor, InterceptorAction, ActionType
from ..driftcop_proxy.message import MCPMessage, MessageType, MessageDirection
from ..driftcop_proxy.session import ProxySession

logger = logging.getLogger(__name__)


class FilterType(Enum):
    """Filter types for boolean logic"""
    AND = "and"
    OR = "or"
    NOT = "not"
    DIRECTION = "direction"
    MESSAGE_TYPE = "message_type"
    METHOD = "method"
    REQUEST_METHOD = "request_method"  # For response filtering
    HAS_PARAM = "has_param"
    PARAM_EQUALS = "param_equals"
    ALWAYS = "always"
    NEVER = "never"


@dataclass
class FilterCondition:
    """Single filter condition"""
    type: FilterType
    value: Optional[Any] = None
    conditions: Optional[List['FilterCondition']] = None
    
    def evaluate(self, message: MCPMessage, context: Dict[str, Any]) -> bool:
        """
        Evaluate filter condition
        
        Args:
            message: Message to evaluate
            context: Evaluation context (includes correlated request)
            
        Returns:
            True if condition matches
        """
        if self.type == FilterType.AND:
            return all(c.evaluate(message, context) for c in (self.conditions or []))
        
        elif self.type == FilterType.OR:
            return any(c.evaluate(message, context) for c in (self.conditions or []))
        
        elif self.type == FilterType.NOT:
            return not self.conditions[0].evaluate(message, context) if self.conditions else False
        
        elif self.type == FilterType.DIRECTION:
            return message.direction.value == self.value
        
        elif self.type == FilterType.MESSAGE_TYPE:
            return message.type.value == self.value
        
        elif self.type == FilterType.METHOD:
            return message.method == self.value if message.method else False
        
        elif self.type == FilterType.REQUEST_METHOD:
            # For filtering responses based on original request method
            correlated_request = context.get('correlated_request')
            if correlated_request:
                return correlated_request.method == self.value
            return False
        
        elif self.type == FilterType.HAS_PARAM:
            params = message.params or {}
            return self.value in params
        
        elif self.type == FilterType.PARAM_EQUALS:
            if isinstance(self.value, dict):
                params = message.params or {}
                param_name = self.value.get('param')
                param_value = self.value.get('value')
                return params.get(param_name) == param_value
            return False
        
        elif self.type == FilterType.ALWAYS:
            return True
        
        elif self.type == FilterType.NEVER:
            return False
        
        return False
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FilterCondition':
        """
        Create filter condition from dictionary
        
        Args:
            data: Filter configuration
            
        Returns:
            FilterCondition instance
        """
        filter_type = FilterType(data.get('type', 'always'))
        
        # Handle nested conditions
        conditions = None
        if 'conditions' in data:
            conditions = [cls.from_dict(c) for c in data['conditions']]
        elif 'condition' in data:
            conditions = [cls.from_dict(data['condition'])]
        
        return cls(
            type=filter_type,
            value=data.get('value'),
            conditions=conditions
        )


class FilterInterceptor(MessageInterceptor):
    """
    Filter interceptor with complex boolean logic
    Implements advanced message filtering with boolean logic
    """
    
    name = "filter"
    priority = 5
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        
        # Parse filter logic
        self.filter_logic = self._parse_filter_logic(config.get('filter_logic', {}))
        
        # Actions for match/non-match
        self.match_action = self._parse_action(config.get('match_action', 'allow'))
        self.non_match_action = self._parse_action(config.get('non_match_action', 'allow'))
        
        # Optional sub-interceptor for matched messages
        self.match_interceptor = self._create_sub_interceptor(config.get('match_interceptor'))
        
    def _parse_filter_logic(self, logic: Union[Dict, str]) -> FilterCondition:
        """Parse filter logic configuration"""
        if isinstance(logic, str):
            # Simple string filters
            if logic == "always":
                return FilterCondition(type=FilterType.ALWAYS)
            elif logic == "never":
                return FilterCondition(type=FilterType.NEVER)
            else:
                # Assume it's a method name
                return FilterCondition(type=FilterType.METHOD, value=logic)
        
        elif isinstance(logic, dict):
            return FilterCondition.from_dict(logic)
        
        else:
            # Default to always match
            return FilterCondition(type=FilterType.ALWAYS)
    
    def _parse_action(self, action: Union[str, Dict]) -> Union[ActionType, Dict]:
        """Parse action configuration"""
        if isinstance(action, str):
            # Simple action string
            action_map = {
                'allow': ActionType.ALLOW,
                'send': ActionType.ALLOW,
                'block': ActionType.BLOCK,
                'drop': ActionType.BLOCK,
                'queue': ActionType.QUEUE,
                'manual_approval': ActionType.QUEUE,
                'transform': ActionType.TRANSFORM,
                'return': ActionType.RETURN
            }
            return action_map.get(action.lower(), ActionType.ALLOW)
        
        elif isinstance(action, dict):
            # Complex action with parameters
            return action
        
        return ActionType.ALLOW
    
    def _create_sub_interceptor(self, config: Optional[Dict]) -> Optional[MessageInterceptor]:
        """Create sub-interceptor for matched messages"""
        if not config:
            return None
        
        from .factory import InterceptorFactory
        factory = InterceptorFactory()
        return factory.create(config)
    
    async def intercept(
        self,
        message: MCPMessage,
        session: ProxySession
    ) -> InterceptorAction:
        """
        Apply filter logic and determine action
        
        Args:
            message: Message to filter
            session: Current session
            
        Returns:
            Action based on filter match
        """
        # Build evaluation context
        context = {
            'session': session,
            'correlated_request': getattr(message, '_correlated_request', None)
        }
        
        # Evaluate filter
        matches = self.filter_logic.evaluate(message, context)
        
        logger.debug(f"Filter evaluation for {message.method}: {matches}")
        
        if matches:
            # Apply match action
            if self.match_interceptor:
                # Process through sub-interceptor
                return await self.match_interceptor.process(message, session)
            else:
                return self._create_action(self.match_action, message, "Filter matched")
        else:
            # Apply non-match action
            return self._create_action(self.non_match_action, message, "Filter not matched")
    
    def _create_action(
        self,
        action_config: Union[ActionType, Dict],
        message: MCPMessage,
        reason: str
    ) -> InterceptorAction:
        """Create interceptor action from configuration"""
        if isinstance(action_config, ActionType):
            return InterceptorAction(type=action_config, reason=reason)
        
        elif isinstance(action_config, dict):
            action_type = ActionType(action_config.get('type', 'allow'))
            
            if action_type == ActionType.RETURN:
                # Create synthetic response
                from ..driftcop_proxy.message import create_error_response
                response = create_error_response(
                    message,
                    action_config.get('error_code', -32600),
                    action_config.get('error_message', 'Request blocked by filter')
                )
                return InterceptorAction(
                    type=ActionType.RETURN,
                    response=response,
                    reason=reason
                )
            
            elif action_type == ActionType.TRANSFORM:
                # Transform message
                transformed = self._transform_message(message, action_config.get('transform', {}))
                return InterceptorAction(
                    type=ActionType.TRANSFORM,
                    message=transformed,
                    reason=reason
                )
            
            else:
                return InterceptorAction(type=action_type, reason=reason)
        
        return InterceptorAction(type=ActionType.ALLOW, reason=reason)
    
    def _transform_message(self, message: MCPMessage, transform_config: Dict) -> MCPMessage:
        """Transform message based on configuration"""
        data = message.to_dict()
        
        # Apply transformations
        if 'set_params' in transform_config:
            data['params'] = {**data.get('params', {}), **transform_config['set_params']}
        
        if 'remove_params' in transform_config:
            params = data.get('params', {})
            for param in transform_config['remove_params']:
                params.pop(param, None)
        
        if 'set_method' in transform_config:
            data['method'] = transform_config['set_method']
        
        return MCPMessage.from_dict(data, message.direction)


def create_filter(logic: Dict[str, Any]) -> FilterCondition:
    """
    Helper to create filter conditions
    
    Args:
        logic: Filter logic dictionary
        
    Returns:
        FilterCondition instance
    """
    return FilterCondition.from_dict(logic)


# Common filter presets
FILTER_PRESETS = {
    'sensitive_operations': {
        'type': 'or',
        'conditions': [
            {'type': 'method', 'value': 'tools/call'},
            {'type': 'method', 'value': 'resources/write'},
            {'type': 'method', 'value': 'resources/delete'},
            {'type': 'method', 'value': 'prompts/execute'}
        ]
    },
    'outbound_requests': {
        'type': 'and',
        'conditions': [
            {'type': 'direction', 'value': 'outbound'},
            {'type': 'message_type', 'value': 'request'}
        ]
    },
    'inbound_responses': {
        'type': 'and',
        'conditions': [
            {'type': 'direction', 'value': 'inbound'},
            {'type': 'or', 'conditions': [
                {'type': 'message_type', 'value': 'response_success'},
                {'type': 'message_type', 'value': 'response_failure'}
            ]}
        ]
    },
    'tool_calls': {
        'type': 'and',
        'conditions': [
            {'type': 'method', 'value': 'tools/call'},
            {'type': 'direction', 'value': 'outbound'}
        ]
    },
    'resource_modifications': {
        'type': 'and',
        'conditions': [
            {'type': 'direction', 'value': 'outbound'},
            {'type': 'or', 'conditions': [
                {'type': 'method', 'value': 'resources/write'},
                {'type': 'method', 'value': 'resources/delete'},
                {'type': 'method', 'value': 'resources/update'}
            ]}
        ]
    }
}