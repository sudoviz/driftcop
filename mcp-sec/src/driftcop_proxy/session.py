"""
Session management for proxy connections
"""

import uuid
import time
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, Optional, Any, List
import logging

from .message import MCPMessage, RequestCache

logger = logging.getLogger(__name__)


@dataclass
class SecurityContext:
    """Security context for a session"""
    session_id: str
    client_name: str
    server_name: str
    is_production: bool = False
    has_previous_violations: bool = False
    user_trust_level: str = "medium"  # low, medium, high
    risk_baseline: float = 0.0
    current_risk: float = 0.0
    drift_threshold: float = 0.7
    approval_timeout: int = 300  # seconds
    metadata: Dict[str, Any] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    violations: List[Dict[str, Any]] = field(default_factory=list)
    risk_history: List[float] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'session_id': self.session_id,
            'client_name': self.client_name,
            'server_name': self.server_name,
            'is_production': self.is_production,
            'has_previous_violations': self.has_previous_violations,
            'user_trust_level': self.user_trust_level,
            'risk_baseline': self.risk_baseline,
            'current_risk': self.current_risk,
            'drift_threshold': self.drift_threshold,
            'approval_timeout': self.approval_timeout,
            'metadata': self.metadata
        }


@dataclass
class ProxySession:
    """Represents a proxy session between client and server"""
    id: str
    client_name: str
    server_config: Dict[str, Any]
    security_context: SecurityContext
    created_at: datetime = field(default_factory=datetime.now)
    last_activity: datetime = field(default_factory=datetime.now)
    request_cache: RequestCache = field(default_factory=lambda: RequestCache())
    
    # Statistics
    messages_processed: int = 0
    messages_blocked: int = 0
    messages_transformed: int = 0
    errors: int = 0
    
    # Risk tracking
    risk_history: List[float] = field(default_factory=list)
    violations: List[Dict] = field(default_factory=list)
    
    # Session state
    active: bool = True
    interceptor_chain: Optional[Any] = None
    enforcement_mode: str = "enforce"  # monitor, enforce, interactive
    
    @property
    def metadata(self) -> Dict[str, Any]:
        """Get session metadata"""
        return self.security_context.metadata
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = datetime.now()
        
    def update_risk(self, new_risk: float, alpha: float = 0.3):
        """
        Update session risk with exponential moving average
        
        Args:
            new_risk: New risk score
            alpha: Smoothing factor (0-1)
        """
        self.security_context.current_risk = (
            alpha * new_risk + 
            (1 - alpha) * self.security_context.current_risk
        )
        self.risk_history.append(self.security_context.current_risk)
        
        # Keep only last 100 risk scores
        if len(self.risk_history) > 100:
            self.risk_history = self.risk_history[-100:]
    
    def add_violation(self, violation: Dict):
        """Record a security violation"""
        self.violations.append({
            **violation,
            'timestamp': datetime.now().isoformat()
        })
        self.security_context.has_previous_violations = True
        
        # Keep only last 50 violations
        if len(self.violations) > 50:
            self.violations = self.violations[-50:]
    
    def is_high_risk(self) -> bool:
        """Check if session is high risk"""
        return self.security_context.current_risk > self.security_context.risk_baseline * 1.5
    
    def get_stats(self) -> Dict[str, Any]:
        """Get session statistics"""
        return {
            'session_id': self.id,
            'client': self.client_name,
            'created': self.created_at.isoformat(),
            'last_activity': self.last_activity.isoformat(),
            'messages_processed': self.messages_processed,
            'messages_blocked': self.messages_blocked,
            'messages_transformed': self.messages_transformed,
            'errors': self.errors,
            'current_risk': self.security_context.current_risk,
            'violations_count': len(self.violations),
            'active': self.active
        }


class SessionManager:
    """Manages proxy sessions"""
    
    def __init__(self):
        self.sessions: Dict[str, ProxySession] = {}
        self.client_sessions: Dict[str, List[str]] = {}  # client -> session IDs
        
    async def create_session(
        self,
        client_name: str,
        server_config: Dict[str, Any],
        session_id: Optional[str] = None
    ) -> ProxySession:
        """
        Create a new proxy session
        
        Args:
            client_name: Name of the MCP client
            server_config: Server configuration
            session_id: Optional session ID (generated if not provided)
            
        Returns:
            Created ProxySession
        """
        if not session_id:
            session_id = str(uuid.uuid4())
        
        # Create security context
        security_context = await self._build_security_context(
            session_id, client_name, server_config
        )
        
        # Create session
        session = ProxySession(
            id=session_id,
            client_name=client_name,
            server_config=server_config,
            security_context=security_context
        )
        
        # Store session
        self.sessions[session_id] = session
        
        # Track client sessions
        if client_name not in self.client_sessions:
            self.client_sessions[client_name] = []
        self.client_sessions[client_name].append(session_id)
        
        logger.info(f"Created session {session_id} for client {client_name}")
        
        return session
    
    async def _build_security_context(
        self,
        session_id: str,
        client_name: str,
        server_config: Dict[str, Any]
    ) -> SecurityContext:
        """Build security context for session"""
        # Determine server name
        server_name = server_config.get('name', 'unknown')
        if 'command' in server_config:
            # Extract from command
            cmd = server_config['command']
            if isinstance(cmd, list) and cmd:
                server_name = cmd[0].split('/')[-1]
        
        # Determine trust level based on client
        trust_levels = {
            'claude': 'high',
            'cursor': 'medium',
            'vscode': 'medium',
            'windsurf': 'medium',
            'unknown': 'low'
        }
        user_trust_level = trust_levels.get(client_name.lower(), 'low')
        
        # Determine if production based on environment
        import os
        is_production = os.getenv('DRIFTCOP_ENV', 'development') == 'production'
        
        # Calculate risk baseline
        risk_baseline = 3.0  # Default baseline
        if is_production:
            risk_baseline *= 1.5
        if user_trust_level == 'low':
            risk_baseline *= 1.2
        
        return SecurityContext(
            session_id=session_id,
            client_name=client_name,
            server_name=server_name,
            is_production=is_production,
            user_trust_level=user_trust_level,
            risk_baseline=risk_baseline,
            current_risk=risk_baseline
        )
    
    def get_session(self, session_id: str) -> Optional[ProxySession]:
        """Get session by ID"""
        return self.sessions.get(session_id)
    
    def get_client_sessions(self, client_name: str) -> List[ProxySession]:
        """Get all sessions for a client"""
        session_ids = self.client_sessions.get(client_name, [])
        return [self.sessions[sid] for sid in session_ids if sid in self.sessions]
    
    def close_session(self, session_id: str):
        """Close a session"""
        if session_id in self.sessions:
            session = self.sessions[session_id]
            session.active = False
            
            # Log final stats
            logger.info(f"Closing session {session_id}: {session.get_stats()}")
            
            # Remove from client sessions
            if session.client_name in self.client_sessions:
                self.client_sessions[session.client_name].remove(session_id)
            
            # Remove session
            del self.sessions[session_id]
    
    def cleanup_inactive_sessions(self, timeout: int = 3600):
        """
        Clean up inactive sessions
        
        Args:
            timeout: Inactivity timeout in seconds
        """
        now = datetime.now()
        inactive_sessions = []
        
        for session_id, session in self.sessions.items():
            if (now - session.last_activity).total_seconds() > timeout:
                inactive_sessions.append(session_id)
        
        for session_id in inactive_sessions:
            logger.info(f"Cleaning up inactive session: {session_id}")
            self.close_session(session_id)
        
        return len(inactive_sessions)
    
    def get_all_sessions(self) -> List[ProxySession]:
        """Get all active sessions"""
        return list(self.sessions.values())
    
    def get_stats(self) -> Dict[str, Any]:
        """Get session manager statistics"""
        total_messages = sum(s.messages_processed for s in self.sessions.values())
        total_blocked = sum(s.messages_blocked for s in self.sessions.values())
        total_transformed = sum(s.messages_transformed for s in self.sessions.values())
        total_errors = sum(s.errors for s in self.sessions.values())
        
        return {
            'active_sessions': len(self.sessions),
            'clients': len(self.client_sessions),
            'total_messages': total_messages,
            'total_blocked': total_blocked,
            'total_transformed': total_transformed,
            'total_errors': total_errors,
            'sessions': [s.get_stats() for s in self.sessions.values()]
        }