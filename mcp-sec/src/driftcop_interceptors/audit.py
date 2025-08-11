"""
Audit interceptor for compliance and security auditing
Provides immutable audit trail with cryptographic verification
"""

import json
import hashlib
import hmac
import time
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import sqlite3
import threading
import uuid

from .base import MessageInterceptor, InterceptorAction, ActionType
from ..driftcop_proxy.message import MCPMessage
from ..driftcop_proxy.session import ProxySession

import logging
logger = logging.getLogger(__name__)


@dataclass
class AuditEntry:
    """Represents an audit log entry"""
    id: str
    timestamp: str
    event_type: str
    direction: str
    message_type: str
    method: Optional[str]
    session_id: str
    client: str
    risk_score: float
    action_taken: str
    request_hash: str
    response_hash: Optional[str]
    metadata: Dict[str, Any]
    signature: Optional[str] = None
    previous_hash: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def compute_hash(self) -> str:
        """Compute hash of this entry for chain integrity"""
        # Create deterministic string representation
        data = {
            'id': self.id,
            'timestamp': self.timestamp,
            'event_type': self.event_type,
            'request_hash': self.request_hash,
            'response_hash': self.response_hash,
            'previous_hash': self.previous_hash
        }
        data_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(data_str.encode()).hexdigest()
    
    def sign(self, secret_key: str) -> str:
        """Sign this entry with HMAC"""
        entry_hash = self.compute_hash()
        signature = hmac.new(
            secret_key.encode(),
            entry_hash.encode(),
            hashlib.sha256
        ).hexdigest()
        self.signature = signature
        return signature


class AuditInterceptor(MessageInterceptor):
    """
    Compliance-focused audit interceptor
    Provides immutable audit trail with signatures
    """
    
    name = "audit"
    priority = 2  # Low priority - runs near the end
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        
        # Audit configuration
        self.enabled = config.get('enabled', True)
        self.compliance_mode = config.get('compliance_mode', 'SOC2')
        self.include_request = config.get('include_request', True)
        self.include_response = config.get('include_response', True)
        self.include_metadata = config.get('include_metadata', True)
        self.hash_messages = config.get('hash_messages', True)
        self.sign_logs = config.get('sign_logs', False)
        self.immutable_storage = config.get('immutable_storage', False)
        self.retention_days = config.get('retention_days', 90)
        self.alert_on_violations = config.get('alert_on_violations', False)
        
        # Secret key for signing (should be loaded from secure storage)
        self.secret_key = config.get('secret_key', self._generate_secret_key())
        
        # Storage configuration
        storage_path = config.get('storage_path', '~/.driftcop/audit')
        self.storage_path = Path(storage_path).expanduser()
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # Database for audit entries
        self.db_path = self.storage_path / 'audit.db'
        self.db_lock = threading.Lock()
        self._init_database()
        
        # Chain integrity
        self.last_hash = self._get_last_hash()
        
        # Statistics
        self.entries_created = 0
        self.violations_detected = 0
        
        # Compliance configurations
        self.compliance_configs = {
            'SOC2': {
                'retention_days': 90,
                'require_signatures': True,
                'immutable': True,
                'fields': ['timestamp', 'user', 'action', 'result', 'ip']
            },
            'HIPAA': {
                'retention_days': 2190,  # 6 years
                'require_signatures': True,
                'immutable': True,
                'encrypt_phi': True,
                'fields': ['timestamp', 'user', 'patient_id', 'action', 'phi_accessed']
            },
            'PCI-DSS': {
                'retention_days': 365,
                'require_signatures': True,
                'immutable': True,
                'mask_card_numbers': True,
                'fields': ['timestamp', 'user', 'action', 'card_present', 'merchant_id']
            },
            'GDPR': {
                'retention_days': 1095,  # 3 years
                'require_signatures': False,
                'allow_deletion': True,
                'anonymize_pii': True,
                'fields': ['timestamp', 'purpose', 'legal_basis', 'data_categories']
            },
            'ISO27001': {
                'retention_days': 1095,
                'require_signatures': True,
                'immutable': False,
                'fields': ['timestamp', 'asset', 'threat', 'vulnerability', 'risk_level']
            }
        }
        
        # Apply compliance mode settings
        if self.compliance_mode in self.compliance_configs:
            compliance = self.compliance_configs[self.compliance_mode]
            self.retention_days = compliance.get('retention_days', self.retention_days)
            self.sign_logs = compliance.get('require_signatures', self.sign_logs)
            self.immutable_storage = compliance.get('immutable', self.immutable_storage)
    
    def _generate_secret_key(self) -> str:
        """Generate a secret key for signing"""
        import secrets
        return secrets.token_hex(32)
    
    def _init_database(self):
        """Initialize SQLite database for audit entries"""
        with self.db_lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create audit table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    direction TEXT,
                    message_type TEXT,
                    method TEXT,
                    session_id TEXT,
                    client TEXT,
                    risk_score REAL,
                    action_taken TEXT,
                    request_hash TEXT,
                    response_hash TEXT,
                    metadata TEXT,
                    signature TEXT,
                    previous_hash TEXT,
                    entry_hash TEXT,
                    created_at REAL
                )
            ''')
            
            # Create indices for common queries
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_log(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_session ON audit_log(session_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_client ON audit_log(client)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_event ON audit_log(event_type)')
            
            # Create compliance metadata table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS compliance_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at REAL
                )
            ''')
            
            conn.commit()
            conn.close()
    
    def _get_last_hash(self) -> Optional[str]:
        """Get the hash of the last audit entry for chain integrity"""
        with self.db_lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT entry_hash FROM audit_log
                ORDER BY created_at DESC
                LIMIT 1
            ''')
            
            result = cursor.fetchone()
            conn.close()
            
            return result[0] if result else None
    
    def _save_entry(self, entry: AuditEntry):
        """Save audit entry to database"""
        with self.db_lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Compute entry hash
            entry_hash = entry.compute_hash()
            
            cursor.execute('''
                INSERT INTO audit_log (
                    id, timestamp, event_type, direction, message_type,
                    method, session_id, client, risk_score, action_taken,
                    request_hash, response_hash, metadata, signature,
                    previous_hash, entry_hash, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                entry.id,
                entry.timestamp,
                entry.event_type,
                entry.direction,
                entry.message_type,
                entry.method,
                entry.session_id,
                entry.client,
                entry.risk_score,
                entry.action_taken,
                entry.request_hash,
                entry.response_hash,
                json.dumps(entry.metadata),
                entry.signature,
                entry.previous_hash,
                entry_hash,
                time.time()
            ))
            
            conn.commit()
            conn.close()
            
            # Update last hash for chain
            self.last_hash = entry_hash
    
    def _hash_message(self, message: MCPMessage) -> str:
        """Create hash of message content"""
        if not self.hash_messages:
            return ""
        
        message_str = json.dumps(message.to_dict(), sort_keys=True)
        return hashlib.sha256(message_str.encode()).hexdigest()
    
    async def intercept(
        self,
        message: MCPMessage,
        session: ProxySession
    ) -> InterceptorAction:
        """
        Create audit log entry for message
        
        Args:
            message: Message to audit
            session: Current session
            
        Returns:
            Always returns ALLOW action
        """
        if not self.enabled:
            return InterceptorAction(type=ActionType.ALLOW)
        
        # Determine event type
        event_type = 'message'
        if message.method and 'tool' in message.method:
            event_type = 'tool_call'
        elif message.method and 'resource' in message.method:
            event_type = 'resource_access'
        elif message.error:
            event_type = 'error'
        
        # Prepare metadata
        metadata = {
            'compliance_mode': self.compliance_mode,
            'interceptor_chain': session.metadata.get('interceptor_chain', [])
        }
        
        if self.include_metadata:
            metadata.update({
                'security_findings': session.security_context.findings[-5:],
                'violations': session.security_context.violations[-5:],
                'risk_history': session.security_context.risk_history[-10:]
            })
        
        # Check for violations
        if session.security_context.violations:
            self.violations_detected += 1
            if self.alert_on_violations:
                await self._send_violation_alert(session, message)
        
        # Create audit entry
        entry = AuditEntry(
            id=str(uuid.uuid4()),
            timestamp=datetime.now().isoformat(),
            event_type=event_type,
            direction=message.direction.value,
            message_type=message.type.value,
            method=message.method,
            session_id=session.id,
            client=session.client_name,
            risk_score=session.security_context.current_risk,
            action_taken='allowed',  # Will be updated by other interceptors
            request_hash=self._hash_message(message) if self.include_request else '',
            response_hash='',  # Will be updated for responses
            metadata=metadata,
            previous_hash=self.last_hash
        )
        
        # Sign entry if configured
        if self.sign_logs:
            entry.sign(self.secret_key)
        
        # Save to database
        self._save_entry(entry)
        self.entries_created += 1
        
        # Clean old entries based on retention
        if self.entries_created % 1000 == 0:
            await self._cleanup_old_entries()
        
        return InterceptorAction(
            type=ActionType.ALLOW,
            metadata={'audit_id': entry.id, 'audited': True}
        )
    
    async def _send_violation_alert(self, session: ProxySession, message: MCPMessage):
        """Send alert for security violations"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'session_id': session.id,
            'client': session.client_name,
            'method': message.method,
            'risk_score': session.security_context.current_risk,
            'violations': session.security_context.violations[-5:]
        }
        
        # Log alert
        logger.warning(f"SECURITY VIOLATION ALERT: {json.dumps(alert)}")
        
        # Could also send to external systems (email, Slack, SIEM, etc.)
    
    async def _cleanup_old_entries(self):
        """Remove entries older than retention period"""
        if self.immutable_storage:
            # Don't delete in immutable mode, just mark as archived
            return
        
        cutoff_time = time.time() - (self.retention_days * 86400)
        
        with self.db_lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Archive old entries before deletion
            cursor.execute('''
                SELECT * FROM audit_log
                WHERE created_at < ?
            ''', (cutoff_time,))
            
            old_entries = cursor.fetchall()
            
            if old_entries:
                # Save to archive file
                archive_path = self.storage_path / f'archive_{int(time.time())}.json'
                with open(archive_path, 'w') as f:
                    json.dump([dict(zip([d[0] for d in cursor.description], row)) 
                              for row in old_entries], f)
                
                # Delete from main database
                cursor.execute('DELETE FROM audit_log WHERE created_at < ?', (cutoff_time,))
                conn.commit()
                
                logger.info(f"Archived {len(old_entries)} old audit entries")
            
            conn.close()
    
    def verify_chain_integrity(self) -> bool:
        """Verify the integrity of the audit chain"""
        with self.db_lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, entry_hash, previous_hash, signature
                FROM audit_log
                ORDER BY created_at ASC
            ''')
            
            entries = cursor.fetchall()
            conn.close()
        
        if not entries:
            return True
        
        # Verify chain
        previous_hash = None
        for entry_id, entry_hash, prev_hash, signature in entries:
            if previous_hash and prev_hash != previous_hash:
                logger.error(f"Chain integrity broken at entry {entry_id}")
                return False
            previous_hash = entry_hash
        
        return True
    
    def get_stats(self) -> Dict[str, Any]:
        """Get audit statistics"""
        with self.db_lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM audit_log')
            total_entries = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(DISTINCT session_id) FROM audit_log')
            unique_sessions = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(DISTINCT client) FROM audit_log')
            unique_clients = cursor.fetchone()[0]
            
            conn.close()
        
        return {
            'total_entries': total_entries,
            'entries_created': self.entries_created,
            'violations_detected': self.violations_detected,
            'unique_sessions': unique_sessions,
            'unique_clients': unique_clients,
            'compliance_mode': self.compliance_mode,
            'retention_days': self.retention_days,
            'chain_valid': self.verify_chain_integrity(),
            'db_size': self.db_path.stat().st_size if self.db_path.exists() else 0
        }
    
    def export_audit_log(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        output_path: Optional[Path] = None
    ) -> Path:
        """Export audit log for compliance reporting"""
        with self.db_lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            query = 'SELECT * FROM audit_log WHERE 1=1'
            params = []
            
            if start_date:
                query += ' AND timestamp >= ?'
                params.append(start_date.isoformat())
            
            if end_date:
                query += ' AND timestamp <= ?'
                params.append(end_date.isoformat())
            
            query += ' ORDER BY created_at ASC'
            
            cursor.execute(query, params)
            entries = cursor.fetchall()
            
            # Get column names
            columns = [d[0] for d in cursor.description]
            
            conn.close()
        
        # Convert to list of dicts
        audit_data = [dict(zip(columns, row)) for row in entries]
        
        # Create export
        if not output_path:
            output_path = self.storage_path / f'audit_export_{int(time.time())}.json'
        
        export = {
            'export_timestamp': datetime.now().isoformat(),
            'compliance_mode': self.compliance_mode,
            'total_entries': len(audit_data),
            'date_range': {
                'start': start_date.isoformat() if start_date else None,
                'end': end_date.isoformat() if end_date else None
            },
            'chain_valid': self.verify_chain_integrity(),
            'entries': audit_data
        }
        
        with open(output_path, 'w') as f:
            json.dump(export, f, indent=2)
        
        logger.info(f"Exported {len(audit_data)} audit entries to {output_path}")
        return output_path