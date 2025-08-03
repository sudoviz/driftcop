"""Approval management for changed MCP tools."""

import json
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

from mcp_sec.tracking.tracker import ChangeNotification


class ApprovalStatus(str, Enum):
    """Status of an approval request."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass
class ApprovalRequest:
    """Request for user approval of a change."""
    request_id: str
    notification_id: str
    server_name: str
    change_type: str
    change_summary: str
    risk_level: str  # "low", "medium", "high"
    created_at: str
    expires_at: str
    status: ApprovalStatus
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    rejection_reason: Optional[str] = None


class ApprovalManager:
    """
    Manages approval workflow for MCP tool changes.
    
    Ensures that significant changes require explicit user approval
    before the tools can be used.
    """
    
    def __init__(self, db_path: Path = None):
        """Initialize the approval manager."""
        if db_path is None:
            db_path = Path.home() / ".mcp-sec" / "approvals.db"
        
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize the approvals database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS approval_requests (
                    request_id TEXT PRIMARY KEY,
                    notification_id TEXT NOT NULL,
                    server_name TEXT NOT NULL,
                    change_type TEXT NOT NULL,
                    change_summary TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    approved_by TEXT,
                    approved_at TEXT,
                    rejection_reason TEXT,
                    FOREIGN KEY(notification_id) REFERENCES notifications(notification_id)
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS approval_policies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_pattern TEXT NOT NULL,
                    change_type TEXT NOT NULL,
                    auto_approve BOOLEAN DEFAULT 0,
                    require_multi_approval BOOLEAN DEFAULT 0,
                    approval_count INTEGER DEFAULT 1,
                    expiry_hours INTEGER DEFAULT 72
                )
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_approval_status 
                ON approval_requests(status)
            """)
            
            # Insert default policies
            self._init_default_policies(conn)
    
    def _init_default_policies(self, conn: sqlite3.Connection):
        """Initialize default approval policies."""
        default_policies = [
            # High-risk changes always require approval
            ("*", "permissions_changed", False, False, 1, 72),
            ("*", "tool_removed", False, False, 1, 72),
            ("*", "tool_added", False, False, 1, 72),
            # Tool modifications require approval unless whitelisted
            ("*", "tool_modified", False, False, 1, 72),
        ]
        
        for policy in default_policies:
            conn.execute("""
                INSERT OR IGNORE INTO approval_policies 
                (server_pattern, change_type, auto_approve, require_multi_approval, 
                 approval_count, expiry_hours)
                VALUES (?, ?, ?, ?, ?, ?)
            """, policy)
    
    def create_approval_request(self, notification: ChangeNotification) -> ApprovalRequest:
        """Create an approval request from a change notification."""
        request_id = f"approval-{notification.notification_id}"
        risk_level = self._assess_risk_level(notification)
        change_summary = self._generate_change_summary(notification)
        
        # Get policy for expiry
        policy = self._get_applicable_policy(notification.server_name, notification.change_type)
        expiry_hours = policy.get("expiry_hours", 72)
        
        created_at = datetime.utcnow()
        expires_at = created_at.replace(hour=created_at.hour + expiry_hours)
        
        request = ApprovalRequest(
            request_id=request_id,
            notification_id=notification.notification_id,
            server_name=notification.server_name,
            change_type=notification.change_type,
            change_summary=change_summary,
            risk_level=risk_level,
            created_at=created_at.isoformat(),
            expires_at=expires_at.isoformat(),
            status=ApprovalStatus.PENDING
        )
        
        # Store in database
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO approval_requests
                (request_id, notification_id, server_name, change_type, change_summary,
                 risk_level, created_at, expires_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                request.request_id,
                request.notification_id,
                request.server_name,
                request.change_type,
                request.change_summary,
                request.risk_level,
                request.created_at,
                request.expires_at,
                request.status.value
            ))
        
        return request
    
    def approve_request(self, request_id: str, approved_by: str) -> bool:
        """Approve a change request."""
        with sqlite3.connect(self.db_path) as conn:
            # Check if request exists and is pending
            row = conn.execute(
                "SELECT status, expires_at FROM approval_requests WHERE request_id = ?",
                (request_id,)
            ).fetchone()
            
            if not row:
                return False
            
            status, expires_at = row
            
            # Check if expired
            if datetime.fromisoformat(expires_at) < datetime.utcnow():
                conn.execute(
                    "UPDATE approval_requests SET status = ? WHERE request_id = ?",
                    (ApprovalStatus.EXPIRED.value, request_id)
                )
                return False
            
            # Approve
            conn.execute("""
                UPDATE approval_requests 
                SET status = ?, approved_by = ?, approved_at = ?
                WHERE request_id = ? AND status = ?
            """, (
                ApprovalStatus.APPROVED.value,
                approved_by,
                datetime.utcnow().isoformat(),
                request_id,
                ApprovalStatus.PENDING.value
            ))
            
            return conn.total_changes > 0
    
    def reject_request(self, request_id: str, rejected_by: str, reason: str) -> bool:
        """Reject a change request."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE approval_requests 
                SET status = ?, approved_by = ?, approved_at = ?, rejection_reason = ?
                WHERE request_id = ? AND status = ?
            """, (
                ApprovalStatus.REJECTED.value,
                rejected_by,
                datetime.utcnow().isoformat(),
                reason,
                request_id,
                ApprovalStatus.PENDING.value
            ))
            
            return conn.total_changes > 0
    
    def get_pending_approvals(self) -> List[ApprovalRequest]:
        """Get all pending approval requests."""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("""
                SELECT request_id, notification_id, server_name, change_type,
                       change_summary, risk_level, created_at, expires_at,
                       status, approved_by, approved_at, rejection_reason
                FROM approval_requests
                WHERE status = ?
                ORDER BY created_at DESC
            """, (ApprovalStatus.PENDING.value,)).fetchall()
            
            requests = []
            for row in rows:
                # Check if expired
                if datetime.fromisoformat(row[7]) < datetime.utcnow():
                    conn.execute(
                        "UPDATE approval_requests SET status = ? WHERE request_id = ?",
                        (ApprovalStatus.EXPIRED.value, row[0])
                    )
                    continue
                
                requests.append(ApprovalRequest(
                    request_id=row[0],
                    notification_id=row[1],
                    server_name=row[2],
                    change_type=row[3],
                    change_summary=row[4],
                    risk_level=row[5],
                    created_at=row[6],
                    expires_at=row[7],
                    status=ApprovalStatus(row[8]),
                    approved_by=row[9],
                    approved_at=row[10],
                    rejection_reason=row[11]
                ))
            
            return requests
    
    def is_change_approved(self, notification_id: str) -> bool:
        """Check if a change has been approved."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("""
                SELECT status FROM approval_requests
                WHERE notification_id = ?
                ORDER BY created_at DESC
                LIMIT 1
            """, (notification_id,)).fetchone()
            
            return row and row[0] == ApprovalStatus.APPROVED.value
    
    def _assess_risk_level(self, notification: ChangeNotification) -> str:
        """Assess the risk level of a change."""
        if notification.change_type == "permissions_changed":
            # Permission changes are always high risk
            details = notification.details
            if "process:spawn" in details.get("added", []) or \
               "filesystem:write" in details.get("added", []):
                return "high"
            return "medium"
        
        elif notification.change_type == "tool_removed":
            return "medium"
        
        elif notification.change_type == "tool_added":
            return "high"
        
        elif notification.change_type == "tool_modified":
            # Analyze the specific changes
            changes = notification.details.get("changes", [])
            for change in changes:
                if change.get("field") == "input_schema":
                    return "high"
            return "medium"
        
        return "low"
    
    def _generate_change_summary(self, notification: ChangeNotification) -> str:
        """Generate a human-readable summary of the change."""
        if notification.change_type == "permissions_changed":
            details = notification.details
            added = details.get("added", [])
            removed = details.get("removed", [])
            
            parts = []
            if added:
                parts.append(f"Added permissions: {', '.join(added)}")
            if removed:
                parts.append(f"Removed permissions: {', '.join(removed)}")
            
            return "; ".join(parts)
        
        elif notification.change_type == "tool_added":
            return f"New tool '{notification.details['tool_name']}' added"
        
        elif notification.change_type == "tool_removed":
            return f"Tool '{notification.details['tool_name']}' removed"
        
        elif notification.change_type == "tool_modified":
            tool_name = notification.details.get("tool_name", "unknown")
            changes = notification.details.get("changes", [])
            
            change_types = [c["field"] for c in changes]
            return f"Tool '{tool_name}' modified: {', '.join(change_types)}"
        
        return f"{notification.change_type}: {notification.server_name}"
    
    def _get_applicable_policy(self, server_name: str, change_type: str) -> Dict[str, Any]:
        """Get the applicable approval policy for a change."""
        with sqlite3.connect(self.db_path) as conn:
            # Try exact match first
            row = conn.execute("""
                SELECT auto_approve, require_multi_approval, approval_count, expiry_hours
                FROM approval_policies
                WHERE server_pattern = ? AND change_type = ?
            """, (server_name, change_type)).fetchone()
            
            if not row:
                # Try wildcard
                row = conn.execute("""
                    SELECT auto_approve, require_multi_approval, approval_count, expiry_hours
                    FROM approval_policies
                    WHERE server_pattern = '*' AND change_type = ?
                """, (change_type,)).fetchone()
            
            if row:
                return {
                    "auto_approve": bool(row[0]),
                    "require_multi_approval": bool(row[1]),
                    "approval_count": row[2],
                    "expiry_hours": row[3]
                }
            
            # Default policy
            return {
                "auto_approve": False,
                "require_multi_approval": False,
                "approval_count": 1,
                "expiry_hours": 72
            }