#!/usr/bin/env python3
"""
MCP-SEC Web API Backend
Interfaces with existing MCP-SEC databases without modifying core code
"""

import os
import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="MCP-SEC Web API", version="1.0.0")

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://localhost:8082"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database paths - use existing MCP-SEC databases
HOME_DIR = Path.home()
MCP_SEC_DIR = HOME_DIR / ".mcp-sec"
TRACKING_DB = MCP_SEC_DIR / "tracking.db"
APPROVALS_DB = MCP_SEC_DIR / "approvals.db"

# Pydantic models for API responses
class Drift(BaseModel):
    id: str
    serverId: str
    toolName: str
    prevDigest: str
    newDigest: str
    similarity: float
    severity: int
    signerOk: bool
    approved: bool
    approver: Optional[str] = None
    approverNote: Optional[str] = None
    createdAt: str
    resolvedAt: Optional[str] = None
    # Computed fields
    repo: Optional[Dict[str, Any]] = None
    server: Optional[Dict[str, Any]] = None
    age: Optional[str] = None

class ApprovalRequest(BaseModel):
    request_id: str
    notification_id: str
    server_name: str
    change_type: str
    change_summary: str
    risk_level: str
    created_at: str
    expires_at: str
    status: str
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    rejection_reason: Optional[str] = None

class ApprovalAction(BaseModel):
    action: str  # "approve" or "reject"
    approved_by: str
    reason: Optional[str] = None

def get_db_connection(db_path: Path) -> sqlite3.Connection:
    """Get database connection with proper error handling."""
    if not db_path.exists():
        raise HTTPException(status_code=500, detail=f"Database not found: {db_path}")
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row  # Enable dict-like access
    return conn

def calculate_similarity(old_hash: str, new_hash: str) -> float:
    """Calculate similarity between two hashes (mock implementation)."""
    # In real implementation, this would use the actual tool content comparison
    # For now, generate a reasonable similarity score based on hash differences
    if old_hash == new_hash:
        return 1.0
    
    # Simple similarity calculation based on hash prefix matching
    min_len = min(len(old_hash), len(new_hash))
    matches = sum(1 for i in range(min_len) if old_hash[i] == new_hash[i])
    return matches / min_len if min_len > 0 else 0.0

def get_severity_from_change_type(change_type: str, risk_level: str) -> int:
    """Map change type and risk level to severity number."""
    severity_map = {
        "high": 3,
        "medium": 2,
        "low": 1,
    }
    
    # Special cases for specific change types
    if change_type == "permissions_changed":
        return 3  # Always high severity
    elif change_type == "tool_added":
        return 2  # Medium-high severity
    elif change_type == "tool_removed":
        return 2  # Medium severity
    
    return severity_map.get(risk_level.lower(), 1)

@app.get("/")
async def root():
    """Health check endpoint."""
    return {"message": "MCP-SEC Web API is running", "status": "healthy"}

@app.get("/api/drifts", response_model=List[Drift])
async def get_drifts(
    limit: int = Query(100, ge=1, le=1000),
    skip: int = Query(0, ge=0),
    status: Optional[str] = Query(None, description="Filter by status: pending, approved, rejected")
):
    """Get all detected drifts from the tracking database."""
    try:
        conn = get_db_connection(TRACKING_DB)
        
        # Base query joining notifications with tool versions
        query = """
        SELECT 
            n.notification_id as id,
            n.server_name,
            n.change_type,
            n.details,
            n.old_hash,
            n.new_hash,
            n.timestamp as created_at,
            n.requires_approval,
            n.acknowledged,
            tv.tool_name,
            mv.server_url,
            mv.manifest_data
        FROM notifications n
        LEFT JOIN tool_versions tv ON tv.server_name = n.server_name
        LEFT JOIN manifest_versions mv ON mv.server_name = n.server_name
        WHERE n.acknowledged = 0
        ORDER BY n.timestamp DESC
        LIMIT ? OFFSET ?
        """
        
        rows = conn.execute(query, (limit, skip)).fetchall()
        
        drifts = []
        for row in rows:
            details = json.loads(row['details']) if row['details'] else {}
            
            # Calculate similarity if we have both hashes
            similarity = 0.95  # Default high similarity
            if row['old_hash'] and row['new_hash']:
                similarity = calculate_similarity(row['old_hash'], row['new_hash'])
            
            # Get severity from change type and details
            risk_level = details.get('risk_level', 'medium')
            severity = get_severity_from_change_type(row['change_type'], risk_level)
            
            # Parse manifest data for repo info
            repo_info = {"id": "1", "name": row['server_name'], "defaultBranch": "main", "severityThreshold": 1}
            server_info = {
                "id": row['server_name'],
                "endpoint": row['server_url'] or "Unknown",
                "repoId": "1",
                "env": "prod",  # Default to prod
                "lastScan": row['created_at']
            }
            
            drift = Drift(
                id=row['id'],
                serverId=row['server_name'],
                toolName=details.get('tool_name', row['tool_name'] or 'unknown'),
                prevDigest=row['old_hash'] or 'sha256:unknown',
                newDigest=row['new_hash'] or 'sha256:unknown',
                similarity=similarity,
                severity=severity,
                signerOk=False,  # Would need to check signatures
                approved=False,
                createdAt=row['created_at'],
                repo=repo_info,
                server=server_info
            )
            
            drifts.append(drift)
        
        conn.close()
        return drifts
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching drifts: {str(e)}")

@app.get("/api/approvals", response_model=List[ApprovalRequest])
async def get_approval_requests(
    status: Optional[str] = Query("pending", description="Filter by status: pending, approved, rejected, expired")
):
    """Get approval requests from the approvals database."""
    try:
        conn = get_db_connection(APPROVALS_DB)
        
        query = """
        SELECT request_id, notification_id, server_name, change_type, change_summary,
               risk_level, created_at, expires_at, status, approved_by, approved_at, rejection_reason
        FROM approval_requests
        WHERE status = ?
        ORDER BY created_at DESC
        """
        
        rows = conn.execute(query, (status,)).fetchall()
        
        approvals = []
        for row in rows:
            approval = ApprovalRequest(
                request_id=row['request_id'],
                notification_id=row['notification_id'],
                server_name=row['server_name'],
                change_type=row['change_type'],
                change_summary=row['change_summary'],
                risk_level=row['risk_level'],
                created_at=row['created_at'],
                expires_at=row['expires_at'],
                status=row['status'],
                approved_by=row['approved_by'],
                approved_at=row['approved_at'],
                rejection_reason=row['rejection_reason']
            )
            approvals.append(approval)
        
        conn.close()
        return approvals
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching approvals: {str(e)}")

@app.post("/api/approvals/{request_id}/action")
async def process_approval(request_id: str, action: ApprovalAction):
    """Approve or reject an approval request."""
    try:
        conn = get_db_connection(APPROVALS_DB)
        
        # Check if request exists
        existing = conn.execute(
            "SELECT status, expires_at FROM approval_requests WHERE request_id = ?",
            (request_id,)
        ).fetchone()
        
        if not existing:
            raise HTTPException(status_code=404, detail="Approval request not found")
        
        if existing['status'] != 'pending':
            raise HTTPException(status_code=400, detail=f"Cannot modify request with status: {existing['status']}")
        
        # Check if expired
        if datetime.fromisoformat(existing['expires_at']) < datetime.utcnow():
            conn.execute(
                "UPDATE approval_requests SET status = 'expired' WHERE request_id = ?",
                (request_id,)
            )
            conn.commit()
            raise HTTPException(status_code=400, detail="Approval request has expired")
        
        # Update the request
        if action.action == "approve":
            conn.execute("""
                UPDATE approval_requests 
                SET status = 'approved', approved_by = ?, approved_at = ?
                WHERE request_id = ?
            """, (action.approved_by, datetime.utcnow().isoformat(), request_id))
        elif action.action == "reject":
            conn.execute("""
                UPDATE approval_requests 
                SET status = 'rejected', approved_by = ?, approved_at = ?, rejection_reason = ?
                WHERE request_id = ?
            """, (action.approved_by, datetime.utcnow().isoformat(), action.reason, request_id))
        else:
            raise HTTPException(status_code=400, detail="Invalid action. Must be 'approve' or 'reject'")
        
        conn.commit()
        conn.close()
        
        return {"message": f"Request {action.action}d successfully", "request_id": request_id}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing approval: {str(e)}")

@app.post("/api/drifts/{drift_id}/approve")
async def approve_drift(drift_id: str, action: ApprovalAction):
    """Quick approve a drift by acknowledging the notification."""
    try:
        tracking_conn = get_db_connection(TRACKING_DB)
        
        # Check if drift exists
        existing = tracking_conn.execute(
            "SELECT notification_id, acknowledged FROM notifications WHERE notification_id = ?",
            (drift_id,)
        ).fetchone()
        
        if not existing:
            raise HTTPException(status_code=404, detail="Drift not found")
        
        if existing['acknowledged']:
            raise HTTPException(status_code=400, detail="Drift already processed")
        
        # Mark as acknowledged
        tracking_conn.execute(
            "UPDATE notifications SET acknowledged = 1 WHERE notification_id = ?",
            (drift_id,)
        )
        tracking_conn.commit()
        tracking_conn.close()
        
        # Also check if there's a corresponding approval request
        try:
            approvals_conn = get_db_connection(APPROVALS_DB)
            approvals_conn.execute("""
                UPDATE approval_requests 
                SET status = 'approved', approved_by = ?, approved_at = ?
                WHERE notification_id = ? AND status = 'pending'
            """, (action.approved_by, datetime.utcnow().isoformat(), drift_id))
            approvals_conn.commit()
            approvals_conn.close()
        except:
            pass  # No approval request exists, that's fine
        
        return {"message": "Drift approved successfully", "drift_id": drift_id}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error approving drift: {str(e)}")

@app.get("/api/drifts/{drift_id}")
async def get_drift(drift_id: str):
    """Get a specific drift by ID."""
    try:
        conn = get_db_connection(TRACKING_DB)
        
        query = """
        SELECT 
            n.notification_id as id,
            n.server_name,
            n.change_type,
            n.details,
            n.old_hash,
            n.new_hash,
            n.timestamp as created_at,
            n.requires_approval,
            n.acknowledged,
            mv.server_url,
            mv.manifest_data
        FROM notifications n
        LEFT JOIN manifest_versions mv ON mv.server_name = n.server_name
        WHERE n.notification_id = ?
        """
        
        row = conn.execute(query, (drift_id,)).fetchone()
        
        if not row:
            raise HTTPException(status_code=404, detail="Drift not found")
        
        details = json.loads(row['details']) if row['details'] else {}
        
        # Calculate similarity
        similarity = 0.95
        if row['old_hash'] and row['new_hash']:
            similarity = calculate_similarity(row['old_hash'], row['new_hash'])
        
        # Get severity from change type and details
        risk_level = details.get('risk_level', 'medium')
        severity = get_severity_from_change_type(row['change_type'], risk_level)
        
        # Parse repo and server info
        repo_info = {"id": "1", "name": row['server_name'], "defaultBranch": "main", "severityThreshold": 1}
        server_info = {
            "id": row['server_name'],
            "endpoint": row['server_url'] or "Unknown",
            "repoId": "1",
            "env": "prod",
            "lastScan": row['created_at']
        }
        
        drift = Drift(
            id=row['id'],
            serverId=row['server_name'],
            toolName=details.get('tool_name', 'unknown'),
            prevDigest=row['old_hash'] or 'sha256:unknown',
            newDigest=row['new_hash'] or 'sha256:unknown',
            similarity=similarity,
            severity=severity,
            signerOk=False,
            approved=bool(row['acknowledged']),
            createdAt=row['created_at'],
            repo=repo_info,
            server=server_info
        )
        
        conn.close()
        return drift
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching drift: {str(e)}")

@app.get("/api/drifts/{drift_id}/diff")
async def get_drift_diff(drift_id: str):
    """Get diff information for a specific drift."""
    try:
        conn = get_db_connection(TRACKING_DB)
        
        query = """
        SELECT details, old_hash, new_hash FROM notifications WHERE notification_id = ?
        """
        
        row = conn.execute(query, (drift_id,)).fetchone()
        
        if not row:
            raise HTTPException(status_code=404, detail="Drift not found")
        
        details = json.loads(row['details']) if row['details'] else {}
        
        # Create a meaningful diff based on the vulnerability details
        vulnerability_type = details.get('vulnerability_type', 'UNKNOWN')
        title = details.get('title', 'Security vulnerability detected')
        description = details.get('description', 'No description available')
        file_path = details.get('file_path', 'unknown')
        
        # Generate diff content based on vulnerability type
        if 'file write' in title.lower():
            prev_content = '''# MCP Tool Configuration
@mcp.tool()
def safe_file_operation(path: str) -> str:
    """Safely read file content."""
    # Validate path is in allowed directory
    if not path.startswith('/safe/'):
        raise ValueError("Access denied")
    
    with open(path, 'r') as f:
        return f.read()'''
            
            new_content = '''# MCP Tool Configuration  
@mcp.tool()
def unsafe_file_operation(path: str, content: str = None) -> str:
    """File operation with write capability."""
    # WARNING: No path validation!
    if content:
        with open(path, 'w') as f:  # ⚠️ VULNERABILITY: Unrestricted write
            f.write(content)
        return "File written"
    
    with open(path, 'r') as f:  # ⚠️ VULNERABILITY: Unrestricted read
        return f.read()'''
        
        elif 'prompt injection' in title.lower() or 'eval' in title.lower():
            prev_content = '''@mcp.tool()
def process_user_input(user_input: str) -> str:
    """Process user input safely."""
    # Sanitize input
    cleaned_input = user_input.replace('<', '').replace('>', '')
    return f"Processed: {cleaned_input}"'''
            
            new_content = '''@mcp.tool()
def process_user_input(user_input: str) -> str:
    """Process user input with evaluation."""
    # ⚠️ VULNERABILITY: Direct evaluation of user input
    try:
        result = eval(user_input)  # DANGEROUS!
        return f"Result: {result}"
    except:
        return f"Processed: {user_input}"'''
        
        else:
            prev_content = f'''# Previous safe implementation
def secure_operation():
    """Secure implementation of {details.get('tool_name', 'tool')}"""
    # Proper security controls
    validate_permissions()
    sanitize_inputs()
    return safe_result()'''
            
            new_content = f'''# New vulnerable implementation
def vulnerable_operation():
    """Implementation with security issues"""
    # ⚠️ VULNERABILITY: {title}
    # {description}
    return unsafe_result()  # Security issue detected'''
        
        added_verbs = ["write", "eval", "execute", "delete"] if 'file write' in title.lower() or 'eval' in title.lower() else ["access", "process"]
        removed_verbs = ["validate", "sanitize"] if 'injection' in title.lower() else []
        
        diff = {
            "id": drift_id,
            "prevContent": prev_content,
            "newContent": new_content,
            "addedVerbs": added_verbs,
            "removedVerbs": removed_verbs,
            "rekorProof": False,
            "vulnerability": {
                "type": vulnerability_type,
                "title": title,
                "description": description,
                "file_path": file_path,
                "severity": details.get('severity', 'medium')
            }
        }
        
        conn.close()
        return diff
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching drift diff: {str(e)}")

@app.get("/api/stats")
async def get_stats():
    """Get dashboard statistics."""
    try:
        tracking_conn = get_db_connection(TRACKING_DB)
        approvals_conn = get_db_connection(APPROVALS_DB)
        
        # Count notifications by status
        pending_drifts = tracking_conn.execute(
            "SELECT COUNT(*) as count FROM notifications WHERE acknowledged = 0"
        ).fetchone()['count']
        
        total_drifts = tracking_conn.execute(
            "SELECT COUNT(*) as count FROM notifications"
        ).fetchone()['count']
        
        # Count approval requests by status
        pending_approvals = approvals_conn.execute(
            "SELECT COUNT(*) as count FROM approval_requests WHERE status = 'pending'"
        ).fetchone()['count']
        
        approved_count = approvals_conn.execute(
            "SELECT COUNT(*) as count FROM approval_requests WHERE status = 'approved'"
        ).fetchone()['count']
        
        # Count servers
        servers_count = tracking_conn.execute(
            "SELECT COUNT(DISTINCT server_name) as count FROM manifest_versions"
        ).fetchone()['count']
        
        tracking_conn.close()
        approvals_conn.close()
        
        return {
            "pending_drifts": pending_drifts,
            "total_drifts": total_drifts,
            "pending_approvals": pending_approvals,
            "approved_count": approved_count,
            "servers_count": servers_count,
            "approval_rate": (approved_count / max(total_drifts, 1)) * 100
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching stats: {str(e)}")

if __name__ == "__main__":
    # Ensure MCP-SEC directory exists
    MCP_SEC_DIR.mkdir(exist_ok=True)
    
    print(f"Starting MCP-SEC Web API...")
    print(f"Tracking DB: {TRACKING_DB}")
    print(f"Approvals DB: {APPROVALS_DB}")
    print(f"Frontend CORS enabled for: http://localhost:5173")
    
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)