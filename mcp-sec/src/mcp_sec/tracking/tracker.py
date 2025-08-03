"""Version tracking and change detection for MCP tools."""

import json
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from mcp_sec.models import MCPManifest, MCPTool
from mcp_sec.crypto import compute_tool_digest, compute_manifest_digest


@dataclass
class ChangeNotification:
    """Notification about a tool or manifest change."""
    notification_id: str
    timestamp: str
    server_name: str
    change_type: str  # "tool_added", "tool_modified", "tool_removed", "permissions_changed"
    details: Dict[str, Any]
    old_hash: Optional[str] = None
    new_hash: Optional[str] = None
    requires_approval: bool = True


class VersionTracker:
    """
    Tracks versions and changes in MCP server manifests.
    
    Stores historical data to detect changes and trigger notifications.
    """
    
    def __init__(self, db_path: Path = None):
        """Initialize the version tracker with a database."""
        if db_path is None:
            db_path = Path.home() / ".mcp-sec" / "tracking.db"
        
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize the tracking database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS manifest_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_name TEXT NOT NULL,
                    server_url TEXT NOT NULL,
                    manifest_hash TEXT NOT NULL,
                    manifest_data TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    version TEXT,
                    UNIQUE(server_url, manifest_hash)
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tool_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_name TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    tool_hash TEXT NOT NULL,
                    tool_data TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    manifest_version_id INTEGER,
                    FOREIGN KEY(manifest_version_id) REFERENCES manifest_versions(id),
                    UNIQUE(server_name, tool_name, tool_hash)
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    notification_id TEXT UNIQUE NOT NULL,
                    timestamp TEXT NOT NULL,
                    server_name TEXT NOT NULL,
                    change_type TEXT NOT NULL,
                    details TEXT NOT NULL,
                    old_hash TEXT,
                    new_hash TEXT,
                    requires_approval BOOLEAN DEFAULT 1,
                    acknowledged BOOLEAN DEFAULT 0
                )
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_manifest_server 
                ON manifest_versions(server_url)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_tool_server_name 
                ON tool_versions(server_name, tool_name)
            """)
    
    def track_manifest(self, server_url: str, manifest: MCPManifest) -> List[ChangeNotification]:
        """
        Track a manifest and detect changes.
        
        Returns list of change notifications if changes detected.
        """
        notifications = []
        manifest_hash = compute_manifest_digest(manifest)
        timestamp = datetime.utcnow().isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            # Check if we've seen this exact manifest before
            existing = conn.execute(
                "SELECT id FROM manifest_versions WHERE server_url = ? AND manifest_hash = ?",
                (server_url, manifest_hash)
            ).fetchone()
            
            if existing:
                # No changes
                return notifications
            
            # Get the most recent version for this server
            previous = conn.execute("""
                SELECT manifest_hash, manifest_data 
                FROM manifest_versions 
                WHERE server_url = ? 
                ORDER BY timestamp DESC 
                LIMIT 1
            """, (server_url,)).fetchone()
            
            # Insert new version
            cursor = conn.execute("""
                INSERT INTO manifest_versions 
                (server_name, server_url, manifest_hash, manifest_data, timestamp, version)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                manifest.name,
                server_url,
                manifest_hash,
                json.dumps(manifest.dict()),
                timestamp,
                manifest.version
            ))
            
            manifest_version_id = cursor.lastrowid
            
            if previous:
                # Analyze changes
                old_hash, old_data = previous
                old_manifest = MCPManifest(**json.loads(old_data))
                
                notifications.extend(
                    self._analyze_manifest_changes(old_manifest, manifest, timestamp)
                )
            else:
                # First time seeing this server
                notifications.append(ChangeNotification(
                    notification_id=f"new-server-{manifest_hash[:8]}",
                    timestamp=timestamp,
                    server_name=manifest.name,
                    change_type="new_server",
                    details={
                        "server_url": server_url,
                        "tool_count": len(manifest.tools),
                        "permissions": manifest.permissions
                    },
                    new_hash=manifest_hash,
                    requires_approval=True
                ))
            
            # Track individual tools
            for tool in manifest.tools:
                tool_notifications = self._track_tool(
                    manifest.name, 
                    tool, 
                    manifest_version_id,
                    timestamp,
                    conn
                )
                notifications.extend(tool_notifications)
            
            # Store notifications
            for notification in notifications:
                conn.execute("""
                    INSERT OR IGNORE INTO notifications 
                    (notification_id, timestamp, server_name, change_type, 
                     details, old_hash, new_hash, requires_approval)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    notification.notification_id,
                    notification.timestamp,
                    notification.server_name,
                    notification.change_type,
                    json.dumps(notification.details),
                    notification.old_hash,
                    notification.new_hash,
                    notification.requires_approval
                ))
        
        return notifications
    
    def _track_tool(
        self, 
        server_name: str, 
        tool: MCPTool, 
        manifest_version_id: int,
        timestamp: str,
        conn: sqlite3.Connection
    ) -> List[ChangeNotification]:
        """Track an individual tool and detect changes."""
        notifications = []
        tool_hash = compute_tool_digest(tool)
        
        # Check previous version
        previous = conn.execute("""
            SELECT tool_hash, tool_data
            FROM tool_versions
            WHERE server_name = ? AND tool_name = ?
            ORDER BY timestamp DESC
            LIMIT 1
        """, (server_name, tool.name)).fetchone()
        
        # Insert new version
        conn.execute("""
            INSERT OR IGNORE INTO tool_versions
            (server_name, tool_name, tool_hash, tool_data, timestamp, manifest_version_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            server_name,
            tool.name,
            tool_hash,
            json.dumps(tool.dict()),
            timestamp,
            manifest_version_id
        ))
        
        if previous:
            old_hash, old_data = previous
            if old_hash != tool_hash:
                old_tool = MCPTool(**json.loads(old_data))
                
                # Detailed change analysis
                changes = self._analyze_tool_changes(old_tool, tool)
                
                notifications.append(ChangeNotification(
                    notification_id=f"tool-change-{tool.name}-{tool_hash[:8]}",
                    timestamp=timestamp,
                    server_name=server_name,
                    change_type="tool_modified",
                    details={
                        "tool_name": tool.name,
                        "changes": changes
                    },
                    old_hash=old_hash,
                    new_hash=tool_hash,
                    requires_approval=self._requires_approval(changes)
                ))
        
        return notifications
    
    def _analyze_manifest_changes(
        self, 
        old_manifest: MCPManifest, 
        new_manifest: MCPManifest,
        timestamp: str
    ) -> List[ChangeNotification]:
        """Analyze changes between two manifest versions."""
        notifications = []
        
        # Check permission changes
        old_perms = set(old_manifest.permissions)
        new_perms = set(new_manifest.permissions)
        
        added_perms = new_perms - old_perms
        removed_perms = old_perms - new_perms
        
        if added_perms or removed_perms:
            notifications.append(ChangeNotification(
                notification_id=f"perm-change-{new_manifest.name}-{timestamp[:10]}",
                timestamp=timestamp,
                server_name=new_manifest.name,
                change_type="permissions_changed",
                details={
                    "added": list(added_perms),
                    "removed": list(removed_perms)
                },
                requires_approval=True
            ))
        
        # Check for added/removed tools
        old_tools = {t.name for t in old_manifest.tools}
        new_tools = {t.name for t in new_manifest.tools}
        
        for tool_name in new_tools - old_tools:
            tool = next(t for t in new_manifest.tools if t.name == tool_name)
            notifications.append(ChangeNotification(
                notification_id=f"tool-added-{tool_name}-{timestamp[:10]}",
                timestamp=timestamp,
                server_name=new_manifest.name,
                change_type="tool_added",
                details={
                    "tool_name": tool_name,
                    "description": tool.description
                },
                new_hash=compute_tool_digest(tool),
                requires_approval=True
            ))
        
        for tool_name in old_tools - new_tools:
            notifications.append(ChangeNotification(
                notification_id=f"tool-removed-{tool_name}-{timestamp[:10]}",
                timestamp=timestamp,
                server_name=new_manifest.name,
                change_type="tool_removed",
                details={"tool_name": tool_name},
                requires_approval=True
            ))
        
        return notifications
    
    def _analyze_tool_changes(self, old_tool: MCPTool, new_tool: MCPTool) -> List[Dict[str, Any]]:
        """Analyze specific changes between tool versions."""
        changes = []
        
        if old_tool.description != new_tool.description:
            changes.append({
                "field": "description",
                "old": old_tool.description,
                "new": new_tool.description
            })
        
        # Schema changes require deeper analysis
        if json.dumps(old_tool.input_schema, sort_keys=True) != json.dumps(new_tool.input_schema, sort_keys=True):
            changes.append({
                "field": "input_schema",
                "type": "schema_modified",
                "details": self._compare_schemas(old_tool.input_schema, new_tool.input_schema)
            })
        
        return changes
    
    def _compare_schemas(self, old_schema: Dict[str, Any], new_schema: Dict[str, Any]) -> Dict[str, Any]:
        """Compare two schemas and identify differences."""
        return {
            "added_fields": list(set(new_schema.get("properties", {}).keys()) - 
                               set(old_schema.get("properties", {}).keys())),
            "removed_fields": list(set(old_schema.get("properties", {}).keys()) - 
                                 set(new_schema.get("properties", {}).keys())),
            "required_changes": {
                "added": list(set(new_schema.get("required", [])) - 
                            set(old_schema.get("required", []))),
                "removed": list(set(old_schema.get("required", [])) - 
                              set(new_schema.get("required", [])))
            }
        }
    
    def _requires_approval(self, changes: List[Dict[str, Any]]) -> bool:
        """Determine if changes require user approval."""
        # All schema changes require approval
        for change in changes:
            if change["field"] in ["input_schema", "output_schema"]:
                return True
        
        # Description changes might indicate functionality changes
        return True
    
    def get_pending_notifications(self) -> List[ChangeNotification]:
        """Get all unacknowledged notifications."""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("""
                SELECT notification_id, timestamp, server_name, change_type,
                       details, old_hash, new_hash, requires_approval
                FROM notifications
                WHERE acknowledged = 0
                ORDER BY timestamp DESC
            """).fetchall()
            
            notifications = []
            for row in rows:
                notifications.append(ChangeNotification(
                    notification_id=row[0],
                    timestamp=row[1],
                    server_name=row[2],
                    change_type=row[3],
                    details=json.loads(row[4]),
                    old_hash=row[5],
                    new_hash=row[6],
                    requires_approval=bool(row[7])
                ))
            
            return notifications
    
    def acknowledge_notification(self, notification_id: str):
        """Mark a notification as acknowledged."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE notifications SET acknowledged = 1 WHERE notification_id = ?",
                (notification_id,)
            )