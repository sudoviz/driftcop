"""
Transform interceptor for message modification
Native Python implementation for message transformation
"""

import re
import json
import logging
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass

from .base import MessageInterceptor, InterceptorAction, ActionType
from ..driftcop_proxy.message import MCPMessage, MessageType
from ..driftcop_proxy.session import ProxySession

logger = logging.getLogger(__name__)


@dataclass
class TransformRule:
    """Rule for transforming messages"""
    name: str
    condition: Optional[Dict[str, Any]]  # Filter condition
    transform: Dict[str, Any]  # Transformation specification
    
    def matches(self, message: MCPMessage) -> bool:
        """Check if rule applies to message"""
        if not self.condition:
            return True
        
        # Simple condition matching
        for key, value in self.condition.items():
            if key == 'method':
                if message.method != value:
                    return False
            elif key == 'type':
                if message.type.value != value:
                    return False
            elif key == 'direction':
                if message.direction.value != value:
                    return False
            elif key == 'has_param':
                params = message.params or {}
                if value not in params:
                    return False
        
        return True


class TransformInterceptor(MessageInterceptor):
    """
    Transform interceptor for message modification
    Supports various transformation operations
    """
    
    name = "transform"
    priority = 10  # Medium priority
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        
        # Parse transformation rules
        self.rules = self._parse_rules(config.get('rules', []))
        
        # Built-in transformers
        self.transformers = {
            'sanitize': self._sanitize_params,
            'redact': self._redact_sensitive,
            'inject': self._inject_params,
            'rename': self._rename_method,
            'validate': self._validate_and_fix,
            'script': self._run_script
        }
        
        # Custom transform functions
        self.custom_transforms = {}
        
        # Configuration
        self.log_transforms = config.get('log_transforms', True)
        self.fail_on_error = config.get('fail_on_error', False)
    
    def _parse_rules(self, rules_config: List[Dict]) -> List[TransformRule]:
        """Parse transformation rules from configuration"""
        rules = []
        
        for rule_config in rules_config:
            rule = TransformRule(
                name=rule_config.get('name', 'unnamed'),
                condition=rule_config.get('condition'),
                transform=rule_config.get('transform', {})
            )
            rules.append(rule)
        
        return rules
    
    async def intercept(
        self,
        message: MCPMessage,
        session: ProxySession
    ) -> InterceptorAction:
        """
        Apply transformations to message
        
        Args:
            message: Message to transform
            session: Current session
            
        Returns:
            Action with transformed message
        """
        # Check each rule
        transformed = False
        current_message = message
        
        for rule in self.rules:
            if rule.matches(current_message):
                try:
                    new_message = await self._apply_transform(
                        current_message,
                        rule.transform,
                        session
                    )
                    
                    if new_message != current_message:
                        if self.log_transforms:
                            logger.info(f"Applied transform '{rule.name}' to {current_message.method}")
                        
                        current_message = new_message
                        transformed = True
                        
                except Exception as e:
                    logger.error(f"Transform error in rule '{rule.name}': {e}")
                    
                    if self.fail_on_error:
                        return InterceptorAction(
                            type=ActionType.BLOCK,
                            reason=f"Transform failed: {e}"
                        )
        
        if transformed:
            session.messages_transformed += 1
            return InterceptorAction(
                type=ActionType.TRANSFORM,
                message=current_message,
                reason="Message transformed",
                metadata={'transformed': True}
            )
        
        return InterceptorAction(type=ActionType.ALLOW)
    
    async def _apply_transform(
        self,
        message: MCPMessage,
        transform_spec: Dict[str, Any],
        session: ProxySession
    ) -> MCPMessage:
        """Apply transformation specification to message"""
        
        # Get transformation type
        transform_type = transform_spec.get('type', 'custom')
        
        if transform_type in self.transformers:
            # Use built-in transformer
            return await self.transformers[transform_type](message, transform_spec, session)
        elif transform_type == 'custom':
            # Apply custom transformations
            return await self._apply_custom_transform(message, transform_spec)
        else:
            logger.warning(f"Unknown transform type: {transform_type}")
            return message
    
    async def _apply_custom_transform(
        self,
        message: MCPMessage,
        spec: Dict[str, Any]
    ) -> MCPMessage:
        """Apply custom transformation specification"""
        data = message.to_dict()
        
        # Set parameters
        if 'set_params' in spec:
            if 'params' not in data:
                data['params'] = {}
            data['params'].update(spec['set_params'])
        
        # Remove parameters
        if 'remove_params' in spec:
            params = data.get('params', {})
            for param in spec['remove_params']:
                params.pop(param, None)
        
        # Rename method
        if 'set_method' in spec:
            data['method'] = spec['set_method']
        
        # Modify result
        if 'transform_result' in spec and 'result' in data:
            result_transform = spec['transform_result']
            if isinstance(result_transform, dict):
                if isinstance(data['result'], dict):
                    data['result'].update(result_transform)
        
        # Apply regex replacements
        if 'regex_replace' in spec:
            for replace_spec in spec['regex_replace']:
                pattern = replace_spec['pattern']
                replacement = replace_spec['replacement']
                field = replace_spec.get('field', 'params')
                
                if field in data:
                    data_str = json.dumps(data[field])
                    data_str = re.sub(pattern, replacement, data_str)
                    data[field] = json.loads(data_str)
        
        return MCPMessage.from_dict(data, message.direction)
    
    async def _sanitize_params(
        self,
        message: MCPMessage,
        spec: Dict[str, Any],
        session: ProxySession
    ) -> MCPMessage:
        """Sanitize parameters by removing sensitive data"""
        data = message.to_dict()
        params = data.get('params', {})
        
        # List of sensitive parameter names
        sensitive_params = spec.get('sensitive_params', [
            'password', 'token', 'secret', 'api_key', 'auth',
            'credential', 'private_key', 'access_token'
        ])
        
        # Sanitize parameters
        for param in list(params.keys()):
            param_lower = param.lower()
            for sensitive in sensitive_params:
                if sensitive in param_lower:
                    params[param] = '***REDACTED***'
                    break
        
        return MCPMessage.from_dict(data, message.direction)
    
    async def _redact_sensitive(
        self,
        message: MCPMessage,
        spec: Dict[str, Any],
        session: ProxySession
    ) -> MCPMessage:
        """Redact sensitive information from message"""
        data = message.to_dict()
        
        # Patterns to redact
        patterns = spec.get('patterns', [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            r'\b(?:\d{4}[-\s]?){3}\d{4}\b',  # Credit card
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
        ])
        
        # Redact from entire message
        data_str = json.dumps(data)
        for pattern in patterns:
            data_str = re.sub(pattern, '[REDACTED]', data_str)
        
        return MCPMessage.from_dict(json.loads(data_str), message.direction)
    
    async def _inject_params(
        self,
        message: MCPMessage,
        spec: Dict[str, Any],
        session: ProxySession
    ) -> MCPMessage:
        """Inject additional parameters into message"""
        data = message.to_dict()
        
        # Parameters to inject
        inject_params = spec.get('params', {})
        
        # Add session context
        if spec.get('inject_context', False):
            inject_params['_session_id'] = session.id
            inject_params['_client'] = session.client_name
            inject_params['_risk_score'] = session.security_context.current_risk
        
        # Add timestamp
        if spec.get('inject_timestamp', False):
            import datetime
            inject_params['_timestamp'] = datetime.datetime.now().isoformat()
        
        # Inject parameters
        if 'params' not in data:
            data['params'] = {}
        data['params'].update(inject_params)
        
        return MCPMessage.from_dict(data, message.direction)
    
    async def _rename_method(
        self,
        message: MCPMessage,
        spec: Dict[str, Any],
        session: ProxySession
    ) -> MCPMessage:
        """Rename method calls"""
        data = message.to_dict()
        
        # Method mapping
        method_map = spec.get('method_map', {})
        
        if data.get('method') in method_map:
            old_method = data['method']
            new_method = method_map[old_method]
            data['method'] = new_method
            
            logger.info(f"Renamed method: {old_method} -> {new_method}")
        
        return MCPMessage.from_dict(data, message.direction)
    
    async def _validate_and_fix(
        self,
        message: MCPMessage,
        spec: Dict[str, Any],
        session: ProxySession
    ) -> MCPMessage:
        """Validate and fix message structure"""
        data = message.to_dict()
        
        # Required fields
        required_fields = spec.get('required_fields', {})
        
        for field, default_value in required_fields.items():
            if field not in data:
                data[field] = default_value
                logger.debug(f"Added missing field '{field}' with default value")
        
        # Fix common issues
        if spec.get('fix_common_issues', True):
            # Ensure JSON-RPC version
            if 'jsonrpc' not in data:
                data['jsonrpc'] = '2.0'
            
            # Ensure ID for requests
            if message.type == MessageType.REQUEST and 'id' not in data:
                import uuid
                data['id'] = str(uuid.uuid4())
            
            # Ensure params is dict for requests
            if message.type == MessageType.REQUEST and 'params' in data:
                if not isinstance(data['params'], dict):
                    data['params'] = {}
        
        return MCPMessage.from_dict(data, message.direction)
    
    async def _run_script(
        self,
        message: MCPMessage,
        spec: Dict[str, Any],
        session: ProxySession
    ) -> MCPMessage:
        """Run custom Python script for transformation"""
        script = spec.get('script', '')
        
        if not script:
            return message
        
        # Create sandbox globals
        sandbox_globals = {
            'message': message.to_dict(),
            'session': {
                'id': session.id,
                'client': session.client_name,
                'risk_score': session.security_context.current_risk
            },
            'transformed_message': None,
            'action': 'send'
        }
        
        try:
            # Execute script in sandbox
            exec(script, sandbox_globals)
            
            # Check if message was transformed
            if sandbox_globals.get('transformed_message'):
                return MCPMessage.from_dict(
                    sandbox_globals['transformed_message'],
                    message.direction
                )
            
        except Exception as e:
            logger.error(f"Script execution error: {e}")
            if self.fail_on_error:
                raise
        
        return message
    
    def register_custom_transform(
        self,
        name: str,
        transform_func: Callable
    ):
        """Register custom transformation function"""
        self.custom_transforms[name] = transform_func
        logger.info(f"Registered custom transform: {name}")