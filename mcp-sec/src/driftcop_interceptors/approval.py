"""
Manual approval interceptor with file-based approval system
"""

import os
import json
import asyncio
import uuid
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
from enum import Enum
import logging

from .base import MessageInterceptor, InterceptorAction, ActionType
from ..driftcop_proxy.message import MCPMessage, MessageType, create_error_response
from ..driftcop_proxy.session import ProxySession

logger = logging.getLogger(__name__)


class ApprovalStatus(Enum):
    """Approval status"""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    TIMEOUT = "timeout"


class ApprovalInterceptor(MessageInterceptor):
    """
    Manual approval interceptor using file-based workflow
    Implements a comprehensive approval workflow
    """
    
    name = "approval"
    is_stateless = False  # Stateful due to approval workflow
    priority = 20  # High priority to catch before other interceptors
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        
        # Approval directory structure
        base_dir = Path(config.get('approval_path', Path.home() / '.driftcop' / 'approvals'))
        self.pending_dir = base_dir / 'pending'
        self.approved_dir = base_dir / 'approved'
        self.denied_dir = base_dir / 'denied'
        
        # Create directories
        self._ensure_directories()
        
        # Methods requiring approval
        self.require_approval = set(config.get('require_approval', [
            'resources/delete',
            'prompts/execute'
        ]))
        
        # Approval timeout
        self.timeout = config.get('timeout', 300)  # 5 minutes default
        
        # Polling interval
        self.poll_interval = config.get('poll_interval', 1.0)  # 1 second
        
    def _ensure_directories(self):
        """Ensure approval directories exist"""
        for dir_path in [self.pending_dir, self.approved_dir, self.denied_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
    
    def should_process(self, message: MCPMessage) -> bool:
        """Check if message needs approval"""
        # Only process requests that require approval
        return (
            message.type == MessageType.REQUEST and
            message.method in self.require_approval
        )
    
    async def intercept(
        self,
        message: MCPMessage,
        session: ProxySession
    ) -> InterceptorAction:
        """
        Check if message requires approval and handle workflow
        
        Args:
            message: Message to check
            session: Current session
            
        Returns:
            Action based on approval
        """
        if not self.should_process(message):
            return InterceptorAction(type=ActionType.ALLOW)
        
        # Create approval request
        approval_id = await self._create_approval_request(message, session)
        
        logger.info(f"Approval required for {message.method} - ID: {approval_id}")
        
        # Wait for approval decision
        status, details = await self._wait_for_approval(approval_id)
        
        if status == ApprovalStatus.APPROVED:
            logger.info(f"Approval granted for {approval_id}")
            
            # Move to approved directory
            self._move_approval(approval_id, self.pending_dir, self.approved_dir)
            
            # Check if message should be modified
            if details and 'modified_message' in details:
                modified = MCPMessage.from_dict(
                    details['modified_message'],
                    message.direction
                )
                return InterceptorAction(
                    type=ActionType.TRANSFORM,
                    message=modified,
                    reason="Approved with modifications"
                )
            
            return InterceptorAction(
                type=ActionType.ALLOW,
                reason="Manually approved"
            )
        
        elif status == ApprovalStatus.DENIED:
            logger.info(f"Approval denied for {approval_id}")
            
            # Move to denied directory
            self._move_approval(approval_id, self.pending_dir, self.denied_dir)
            
            # Return error response
            reason = details.get('reason', 'Request denied by administrator') if details else 'Request denied'
            
            return InterceptorAction(
                type=ActionType.RETURN,
                response=create_error_response(
                    message,
                    -32600,
                    f"Security violation: {reason}"
                ),
                reason=reason
            )
        
        else:  # TIMEOUT
            logger.warning(f"Approval timeout for {approval_id}")
            
            # Move to denied directory
            self._move_approval(approval_id, self.pending_dir, self.denied_dir)
            
            return InterceptorAction(
                type=ActionType.RETURN,
                response=create_error_response(
                    message,
                    -32600,
                    "Security violation: Approval timeout"
                ),
                reason="Approval timeout"
            )
    
    async def _create_approval_request(
        self,
        message: MCPMessage,
        session: ProxySession
    ) -> str:
        """
        Create approval request file
        
        Args:
            message: Message requiring approval
            session: Current session
            
        Returns:
            Approval ID
        """
        approval_id = str(uuid.uuid4())
        
        # Create approval request data
        request_data = {
            'id': approval_id,
            'timestamp': datetime.now().isoformat(),
            'session_id': session.id,
            'client': session.client_name,
            'method': message.method,
            'message': message.to_dict(),
            'risk_score': session.security_context.current_risk,
            'metadata': {
                'session_violations': len(session.violations),
                'messages_processed': session.messages_processed,
                'user_trust_level': session.security_context.user_trust_level
            }
        }
        
        # Write to pending directory
        approval_file = self.pending_dir / f"{approval_id}.json"
        approval_file.write_text(json.dumps(request_data, indent=2))
        
        # Also create a human-readable file
        readme_file = self.pending_dir / f"{approval_id}.txt"
        readme_text = f"""
APPROVAL REQUEST
================
ID: {approval_id}
Time: {request_data['timestamp']}
Client: {request_data['client']}
Method: {request_data['method']}
Risk Score: {request_data['risk_score']:.2f}

MESSAGE:
{json.dumps(message.to_dict(), indent=2)}

TO APPROVE:
  Move {approval_id}.json to ../approved/

TO DENY:
  Move {approval_id}.json to ../denied/
  Optionally add {approval_id}.reason.txt with denial reason
"""
        readme_file.write_text(readme_text)
        
        return approval_id
    
    async def _wait_for_approval(
        self,
        approval_id: str
    ) -> tuple[ApprovalStatus, Optional[Dict]]:
        """
        Wait for approval decision
        
        Args:
            approval_id: Approval request ID
            
        Returns:
            Tuple of (status, details)
        """
        start_time = asyncio.get_event_loop().time()
        
        while asyncio.get_event_loop().time() - start_time < self.timeout:
            # Check approved directory
            approved_file = self.approved_dir / f"{approval_id}.json"
            if approved_file.exists():
                try:
                    details = json.loads(approved_file.read_text())
                    return ApprovalStatus.APPROVED, details
                except:
                    return ApprovalStatus.APPROVED, None
            
            # Check denied directory
            denied_file = self.denied_dir / f"{approval_id}.json"
            if denied_file.exists():
                # Check for reason file
                reason_file = self.denied_dir / f"{approval_id}.reason.txt"
                reason = None
                if reason_file.exists():
                    reason = reason_file.read_text().strip()
                
                try:
                    details = json.loads(denied_file.read_text())
                    if reason:
                        details['reason'] = reason
                    return ApprovalStatus.DENIED, details
                except:
                    return ApprovalStatus.DENIED, {'reason': reason} if reason else None
            
            # Wait before next check
            await asyncio.sleep(self.poll_interval)
        
        # Timeout
        return ApprovalStatus.TIMEOUT, None
    
    def _move_approval(self, approval_id: str, from_dir: Path, to_dir: Path):
        """Move approval files between directories"""
        files_to_move = [
            f"{approval_id}.json",
            f"{approval_id}.txt",
            f"{approval_id}.reason.txt"
        ]
        
        for filename in files_to_move:
            from_file = from_dir / filename
            if from_file.exists():
                to_file = to_dir / filename
                from_file.rename(to_file)


class ApprovalManager:
    """
    Manager for handling approval requests
    Used by CLI and other interfaces
    """
    
    def __init__(self, base_dir: Optional[Path] = None):
        base_dir = base_dir or Path.home() / '.driftcop' / 'approvals'
        self.pending_dir = base_dir / 'pending'
        self.approved_dir = base_dir / 'approved'
        self.denied_dir = base_dir / 'denied'
        
        # Ensure directories exist
        for dir_path in [self.pending_dir, self.approved_dir, self.denied_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
    
    def list_approvals(self, pending_only: bool = True) -> list[Dict]:
        """List approval requests"""
        approvals = []
        
        if pending_only:
            dirs = [self.pending_dir]
        else:
            dirs = [self.pending_dir, self.approved_dir, self.denied_dir]
        
        for dir_path in dirs:
            for json_file in dir_path.glob("*.json"):
                if json_file.stem.endswith('.reason'):
                    continue
                
                try:
                    data = json.loads(json_file.read_text())
                    data['status'] = dir_path.name
                    approvals.append(data)
                except Exception as e:
                    logger.error(f"Error reading approval {json_file}: {e}")
        
        # Sort by timestamp
        approvals.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        return approvals
    
    def get_approval(self, approval_id: str) -> Optional[Dict]:
        """Get specific approval request"""
        for dir_path in [self.pending_dir, self.approved_dir, self.denied_dir]:
            json_file = dir_path / f"{approval_id}.json"
            if json_file.exists():
                try:
                    data = json.loads(json_file.read_text())
                    data['status'] = dir_path.name
                    return data
                except Exception as e:
                    logger.error(f"Error reading approval {json_file}: {e}")
        return None
    
    def approve(self, approval_id: str, reason: Optional[str] = None) -> bool:
        """Approve a request"""
        pending_file = self.pending_dir / f"{approval_id}.json"
        if not pending_file.exists():
            return False
        
        # Move to approved
        approved_file = self.approved_dir / f"{approval_id}.json"
        pending_file.rename(approved_file)
        
        # Move text file too
        pending_txt = self.pending_dir / f"{approval_id}.txt"
        if pending_txt.exists():
            approved_txt = self.approved_dir / f"{approval_id}.txt"
            pending_txt.rename(approved_txt)
        
        # Add approval reason if provided
        if reason:
            reason_file = self.approved_dir / f"{approval_id}.reason.txt"
            reason_file.write_text(reason)
        
        return True
    
    def deny(self, approval_id: str, reason: str) -> bool:
        """Deny a request"""
        pending_file = self.pending_dir / f"{approval_id}.json"
        if not pending_file.exists():
            return False
        
        # Move to denied
        denied_file = self.denied_dir / f"{approval_id}.json"
        pending_file.rename(denied_file)
        
        # Move text file too
        pending_txt = self.pending_dir / f"{approval_id}.txt"
        if pending_txt.exists():
            denied_txt = self.denied_dir / f"{approval_id}.txt"
            pending_txt.rename(denied_txt)
        
        # Add denial reason
        reason_file = self.denied_dir / f"{approval_id}.reason.txt"
        reason_file.write_text(reason)
        
        return True