"""
Security interceptors integrating DriftCop analyzers
"""

import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass

from .base import MessageInterceptor, InterceptorAction, ActionType
from ..driftcop_proxy.message import MCPMessage, MessageType, create_error_response
from ..driftcop_proxy.session import ProxySession

# Import DriftCop analyzers
from ..mcp_sec.analyzers.tool_poisoning import ToolPoisoningAnalyzer
from ..mcp_sec.analyzers.cross_origin import CrossOriginAnalyzer
from ..mcp_sec.analyzers.toxic_flow import ToxicFlowAnalyzer
from ..mcp_sec.analyzers.semantic_drift import SemanticDriftAnalyzer
from ..mcp_sec.models import Severity

logger = logging.getLogger(__name__)


class SecurityInterceptor(MessageInterceptor):
    """
    Main security interceptor integrating all DriftCop analyzers
    """
    
    name = "security"
    is_cpu_intensive = True  # Run in process pool
    priority = 10  # High priority
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        
        # Check if worker pool is available
        self.worker_pool = None
        self.use_worker_pool = self.config.get('use_worker_pool', False)
        
        # Initialize analyzers (only if not using worker pool)
        if not self.use_worker_pool:
            self.tool_poisoning = ToolPoisoningAnalyzer() if self.config.get('enable_tool_poisoning', True) else None
            self.cross_origin = CrossOriginAnalyzer() if self.config.get('enable_cross_origin', True) else None
            self.toxic_flow = ToxicFlowAnalyzer() if self.config.get('enable_toxic_flow', True) else None
            self.semantic = SemanticDriftAnalyzer() if self.config.get('enable_semantic_drift', True) else None
        else:
            # Analyzers will be initialized in worker processes
            self.enabled_analyzers = []
            if self.config.get('enable_tool_poisoning', True):
                self.enabled_analyzers.append('tool_poisoning')
            if self.config.get('enable_cross_origin', True):
                self.enabled_analyzers.append('cross_origin')
            if self.config.get('enable_toxic_flow', True):
                self.enabled_analyzers.append('toxic_flow')
            if self.config.get('enable_semantic_drift', True):
                self.enabled_analyzers.append('semantic_drift')
        
        # Risk thresholds
        self.block_threshold = self.config.get('block_threshold', 8.0)
        self.review_threshold = self.config.get('review_threshold', 5.0)
        
    def set_worker_pool(self, worker_pool):
        """Set the worker pool for parallel analysis"""
        self.worker_pool = worker_pool
        self.use_worker_pool = True
        logger.info("Security interceptor configured to use worker pool")
    
    async def intercept(
        self,
        message: MCPMessage,
        session: ProxySession
    ) -> InterceptorAction:
        """
        Analyze message for security threats
        """
        # Skip safe methods
        if message.is_safe():
            return InterceptorAction(type=ActionType.ALLOW)
        
        # Use worker pool if available for CPU-intensive analysis
        if self.use_worker_pool and self.worker_pool:
            return await self._intercept_with_worker_pool(message, session)
        
        # Local analysis (without worker pool)
        return await self._intercept_local(message, session)
    
    async def _intercept_with_worker_pool(
        self,
        message: MCPMessage,
        session: ProxySession
    ) -> InterceptorAction:
        """
        Analyze using worker pool for parallel processing
        """
        try:
            # Prepare session context
            session_context = {
                'client_name': session.client_name,
                'session_id': session.id,
                'current_risk': session.security_context.current_risk,
                'message_count': session.messages_processed
            }
            
            # Analyze in worker pool
            result = await self.worker_pool.analyze_async(
                message.to_dict(),
                self.enabled_analyzers,
                session_context
            )
            
            if result.error:
                logger.error(f"Worker pool analysis error: {result.error}")
                # Fall back to local analysis
                return await self._intercept_local(message, session)
            
            # Process findings
            risk_score = sum(result.risk_scores.values())
            
            # Update session risk
            session.update_risk(risk_score)
            
            # Determine action based on risk
            if risk_score >= self.block_threshold:
                # Find critical finding
                critical_finding = next(
                    (f for f in result.findings if f['severity'] == 'critical'),
                    None
                )
                reason = critical_finding['title'] if critical_finding else "High security risk detected"
                
                # Record violation
                session.add_violation({
                    'type': 'blocked',
                    'method': message.method,
                    'risk_score': risk_score,
                    'findings': result.findings
                })
                
                return InterceptorAction(
                    type=ActionType.BLOCK,
                    reason=reason,
                    metadata={
                        'risk_score': risk_score,
                        'findings': result.findings,
                        'processing_time': result.processing_time
                    }
                )
            
            elif risk_score >= self.review_threshold:
                # Requires review
                return InterceptorAction(
                    type=ActionType.REVIEW,
                    reason="Medium security risk - requires review",
                    metadata={
                        'risk_score': risk_score,
                        'findings': result.findings,
                        'processing_time': result.processing_time
                    }
                )
            
            # Allow with monitoring
            return InterceptorAction(
                type=ActionType.ALLOW,
                metadata={
                    'risk_score': risk_score,
                    'findings': result.findings,
                    'processing_time': result.processing_time
                }
            )
            
        except Exception as e:
            logger.error(f"Worker pool analysis failed: {e}")
            # Fall back to local analysis
            return await self._intercept_local(message, session)
    
    async def _intercept_local(
        self,
        message: MCPMessage,
        session: ProxySession
    ) -> InterceptorAction:
        """
        Local analysis without worker pool
        """
        findings = []
        risk_score = 0.0
        
        # Tool poisoning detection for tools/list responses
        if message.method == "tools/list" and message.type == MessageType.RESPONSE_SUCCESS:
            if hasattr(self, 'tool_poisoning') and self.tool_poisoning:
                result = await self._analyze_tool_poisoning(message)
                if result:
                    findings.extend(result['findings'])
                    risk_score += result['risk_score']
        
        # Cross-origin attack detection
        if hasattr(self, 'cross_origin') and self.cross_origin and message.is_sensitive():
            result = await self._analyze_cross_origin(message, session)
            if result:
                findings.extend(result['findings'])
                risk_score += result['risk_score']
        
        # Toxic flow detection
        if hasattr(self, 'toxic_flow') and self.toxic_flow:
            result = await self._analyze_toxic_flow(message, session)
            if result:
                findings.extend(result['findings'])
                risk_score += result['risk_score']
        
        # Semantic drift detection
        if hasattr(self, 'semantic') and self.semantic and message.method:
            result = await self._analyze_semantic_drift(message, session)
            if result:
                findings.extend(result['findings'])
                risk_score += result['risk_score']
        
        # Update session risk
        session.update_risk(risk_score)
        
        # Determine action based on risk
        if risk_score >= self.block_threshold:
            # Block high-risk messages
            critical_finding = next((f for f in findings if f.get('severity') == Severity.CRITICAL), None)
            reason = critical_finding['title'] if critical_finding else "High security risk detected"
            
            # Record violation
            session.add_violation({
                'type': 'blocked',
                'reason': reason,
                'risk_score': risk_score,
                'findings': findings
            })
            
            # Return error response if request
            if message.type == MessageType.REQUEST:
                return InterceptorAction(
                    type=ActionType.RETURN,
                    response=create_error_response(message, -32600, f"Security violation: {reason}"),
                    reason=reason,
                    metadata={'findings': findings, 'risk_score': risk_score}
                )
            else:
                return InterceptorAction(
                    type=ActionType.BLOCK,
                    reason=reason,
                    metadata={'findings': findings, 'risk_score': risk_score}
                )
        
        elif risk_score >= self.review_threshold:
            # Queue for manual review
            return InterceptorAction(
                type=ActionType.QUEUE,
                reason="Requires security review",
                metadata={'findings': findings, 'risk_score': risk_score}
            )
        
        # Allow with metadata
        return InterceptorAction(
            type=ActionType.ALLOW,
            metadata={'findings': findings, 'risk_score': risk_score}
        )
    
    async def _analyze_tool_poisoning(self, message: MCPMessage) -> Optional[Dict]:
        """Analyze for tool poisoning"""
        try:
            tools = message.result
            if not isinstance(tools, list):
                return None
            
            findings = []
            risk_score = 0.0
            
            for tool in tools:
                if not isinstance(tool, dict):
                    continue
                
                result = self.tool_poisoning.analyze_tool(tool)
                if result and result.findings:
                    for finding in result.findings:
                        findings.append({
                            'type': 'tool_poisoning',
                            'severity': finding.severity,
                            'title': finding.title,
                            'description': finding.description,
                            'tool': tool.get('name', 'unknown')
                        })
                        
                        # Calculate risk contribution
                        if finding.severity == Severity.CRITICAL:
                            risk_score += 10.0
                        elif finding.severity == Severity.HIGH:
                            risk_score += 7.0
                        elif finding.severity == Severity.MEDIUM:
                            risk_score += 4.0
                        elif finding.severity == Severity.LOW:
                            risk_score += 1.0
            
            return {'findings': findings, 'risk_score': risk_score} if findings else None
            
        except Exception as e:
            logger.error(f"Error in tool poisoning analysis: {e}")
            return None
    
    async def _analyze_cross_origin(self, message: MCPMessage, session: ProxySession) -> Optional[Dict]:
        """Analyze for cross-origin attacks"""
        try:
            # Check if this is a cross-origin attempt
            if message.method == "resources/read":
                params = message.params or {}
                uri = params.get('uri', '')
                
                # Check if accessing resources outside expected scope
                if self.cross_origin.is_cross_origin(uri, session.security_context.server_name):
                    return {
                        'findings': [{
                            'type': 'cross_origin',
                            'severity': Severity.HIGH,
                            'title': 'Cross-origin resource access',
                            'description': f'Attempting to access resource outside server scope: {uri}'
                        }],
                        'risk_score': 8.0
                    }
            
            return None
            
        except Exception as e:
            logger.error(f"Error in cross-origin analysis: {e}")
            return None
    
    async def _analyze_toxic_flow(self, message: MCPMessage, session: ProxySession) -> Optional[Dict]:
        """Analyze for toxic operation flows"""
        try:
            # Track operation sequence
            if not hasattr(session, '_operation_history'):
                session._operation_history = []
            
            session._operation_history.append(message.method)
            
            # Keep last 20 operations
            if len(session._operation_history) > 20:
                session._operation_history = session._operation_history[-20:]
            
            # Check for toxic patterns
            result = self.toxic_flow.analyze_sequence(session._operation_history)
            
            if result and result.is_toxic:
                return {
                    'findings': [{
                        'type': 'toxic_flow',
                        'severity': Severity.HIGH,
                        'title': 'Toxic operation flow detected',
                        'description': result.description,
                        'pattern': result.pattern
                    }],
                    'risk_score': 9.0
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Error in toxic flow analysis: {e}")
            return None
    
    async def _analyze_semantic_drift(self, message: MCPMessage, session: ProxySession) -> Optional[Dict]:
        """Analyze for semantic drift"""
        try:
            # Skip if no baseline
            if not hasattr(session, '_semantic_baseline'):
                session._semantic_baseline = {}
            
            method = message.method
            
            # Calculate drift from baseline
            if method in session._semantic_baseline:
                drift_score = self.semantic.calculate_drift(
                    session._semantic_baseline[method],
                    message.to_dict()
                )
                
                if drift_score > session.security_context.drift_threshold:
                    return {
                        'findings': [{
                            'type': 'semantic_drift',
                            'severity': Severity.MEDIUM,
                            'title': 'Semantic drift detected',
                            'description': f'Method {method} shows {drift_score:.2f} drift from baseline',
                            'drift_score': drift_score
                        }],
                        'risk_score': drift_score * 5.0  # Scale to risk score
                    }
            else:
                # Store baseline
                session._semantic_baseline[method] = message.to_dict()
            
            return None
            
        except Exception as e:
            logger.error(f"Error in semantic drift analysis: {e}")
            return None


class SigstoreInterceptor(MessageInterceptor):
    """
    Sigstore signature verification interceptor
    """
    
    name = "sigstore"
    priority = 15  # Very high priority
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        
        self.verify_manifests = self.config.get('verify_manifests', True)
        self.require_signatures = self.config.get('require_signatures', True)
        self.trusted_keys = self.config.get('trusted_keys', [])
        
        # Import sigstore verifier
        try:
            from ..mcp_sec.sigstore import verify_manifest
            self.verify_manifest = verify_manifest
        except ImportError:
            logger.warning("Sigstore module not available")
            self.verify_manifest = None
    
    async def intercept(
        self,
        message: MCPMessage,
        session: ProxySession
    ) -> InterceptorAction:
        """
        Verify signatures for sensitive operations
        """
        if not self.verify_manifest:
            return InterceptorAction(type=ActionType.ALLOW)
        
        # Check tools/call for signature
        if message.method == "tools/call" and self.require_signatures:
            params = message.params or {}
            tool_name = params.get('name')
            
            if tool_name:
                # Verify tool signature
                is_verified = await self._verify_tool_signature(tool_name, session)
                
                if not is_verified:
                    reason = f"Tool '{tool_name}' signature verification failed"
                    
                    if message.type == MessageType.REQUEST:
                        return InterceptorAction(
                            type=ActionType.RETURN,
                            response=create_error_response(
                                message, -32600, 
                                f"Security violation: {reason}"
                            ),
                            reason=reason
                        )
                    else:
                        return InterceptorAction(
                            type=ActionType.BLOCK,
                            reason=reason
                        )
        
        return InterceptorAction(type=ActionType.ALLOW)
    
    async def _verify_tool_signature(self, tool_name: str, session: ProxySession) -> bool:
        """
        Verify tool signature
        
        Args:
            tool_name: Name of tool to verify
            session: Current session
            
        Returns:
            True if verified
        """
        try:
            # Check if tool has been verified in this session
            if not hasattr(session, '_verified_tools'):
                session._verified_tools = set()
            
            if tool_name in session._verified_tools:
                return True
            
            # Perform verification (simplified for now)
            # In real implementation, would fetch manifest and verify
            logger.info(f"Verifying signature for tool: {tool_name}")
            
            # For now, just check against trusted list
            is_verified = tool_name in self.config.get('trusted_tools', [])
            
            if is_verified:
                session._verified_tools.add(tool_name)
            
            return is_verified
            
        except Exception as e:
            logger.error(f"Error verifying tool signature: {e}")
            return False