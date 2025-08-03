"""Lock file manager for MCP manifests."""

import hashlib
import base64
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

import toml

from mcp_sec.models import MCPManifest
from mcp_sec.crypto.canonicalize import canonicalize_json, create_canonical_tool_representation
from mcp_sec.sigstore import create_dsse_envelope, DSSEEnvelope


@dataclass
class LockEntry:
    """Single entry in the lock file."""
    path: str
    digest: str
    algorithm: str = "sha256"
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    version: Optional[str] = None
    tools: Dict[str, str] = field(default_factory=dict)  # tool_name -> digest
    signature: Optional[Dict[str, Any]] = None  # DSSE envelope
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for TOML serialization."""
        entry = {
            "path": self.path,
            "digest": self.digest,
            "algorithm": self.algorithm,
            "timestamp": self.timestamp
        }
        
        if self.version:
            entry["version"] = self.version
        
        if self.tools:
            entry["tools"] = self.tools
        
        if self.signature:
            entry["signature"] = self.signature
        
        return entry
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LockEntry":
        """Create from dictionary."""
        return cls(**data)


class LockFileManager:
    """Manages .mcpsec-lock.toml files."""
    
    def __init__(self, lockfile_path: Path = None):
        """
        Initialize lock file manager.
        
        Args:
            lockfile_path: Path to lock file. Defaults to .mcpsec-lock.toml
        """
        self.lockfile_path = lockfile_path or Path(".mcpsec-lock.toml")
        self._entries: Dict[str, LockEntry] = {}
        self._metadata: Dict[str, Any] = {}
        
        if self.lockfile_path.exists():
            self.load()
    
    def load(self) -> None:
        """Load existing lock file."""
        try:
            data = toml.loads(self.lockfile_path.read_text())
            
            # Load metadata
            self._metadata = data.get("metadata", {})
            
            # Load entries
            self._entries = {}
            for path, entry_data in data.get("manifest", {}).items():
                self._entries[path] = LockEntry.from_dict(entry_data)
                
        except Exception as e:
            raise ValueError(f"Failed to load lock file: {e}")
    
    def save(self) -> None:
        """Save lock file to disk."""
        # Prepare data structure
        data = {
            "metadata": {
                "version": "1.0",
                "generated": datetime.utcnow().isoformat() + "Z",
                "generator": "mcp-sec",
                **self._metadata
            },
            "manifest": {}
        }
        
        # Add entries
        for path, entry in self._entries.items():
            data["manifest"][path] = entry.to_dict()
        
        # Write with nice formatting
        self.lockfile_path.write_text(toml.dumps(data))
    
    def add_manifest(
        self,
        manifest_path: str,
        manifest: MCPManifest,
        signature: Optional[Dict[str, Any]] = None
    ) -> LockEntry:
        """
        Add or update a manifest in the lock file.
        
        Args:
            manifest_path: Path or URL to the manifest
            manifest: The manifest object
            signature: Optional DSSE signature envelope
        
        Returns:
            The lock entry created
        """
        # Create canonical representation
        canonical_manifest = {
            "name": manifest.name,
            "version": manifest.version,
            "description": manifest.description,
            "author": manifest.author,
            "repository": manifest.repository,
            "permissions": sorted(manifest.permissions) if manifest.permissions else [],
            "tools": []
        }
        
        # Process tools
        tool_digests = {}
        for tool in manifest.tools:
            canonical_tool = create_canonical_tool_representation(tool.dict())
            tool_bytes = canonicalize_json(canonical_tool)
            tool_digest = base64.urlsafe_b64encode(
                hashlib.sha256(tool_bytes).digest()
            ).decode('ascii').rstrip('=')
            
            tool_digests[tool.name] = tool_digest
            canonical_manifest["tools"].append({
                "name": tool.name,
                "digest": tool_digest
            })
        
        # Create canonical bytes and digest
        canonical_bytes = canonicalize_json(canonical_manifest)
        manifest_digest = base64.urlsafe_b64encode(
            hashlib.sha256(canonical_bytes).digest()
        ).decode('ascii').rstrip('=')
        
        # Create lock entry
        entry = LockEntry(
            path=manifest_path,
            digest=manifest_digest,
            version=manifest.version,
            tools=tool_digests,
            signature=signature
        )
        
        self._entries[manifest_path] = entry
        return entry
    
    def get_entry(self, manifest_path: str) -> Optional[LockEntry]:
        """Get a lock entry by path."""
        return self._entries.get(manifest_path)
    
    def verify_manifest(self, manifest_path: str, manifest: MCPManifest) -> bool:
        """
        Verify a manifest against the lock file.
        
        Args:
            manifest_path: Path to the manifest
            manifest: The manifest to verify
        
        Returns:
            True if manifest matches lock file, False otherwise
        """
        entry = self.get_entry(manifest_path)
        if not entry:
            return False
        
        # Create new entry for comparison
        new_entry = self.add_manifest(manifest_path, manifest)
        
        # Compare digests
        return new_entry.digest == entry.digest
    
    def get_changes(self, manifest_path: str, manifest: MCPManifest) -> Dict[str, Any]:
        """
        Get detailed changes between locked and current manifest.
        
        Returns:
            Dictionary with change details
        """
        entry = self.get_entry(manifest_path)
        if not entry:
            return {"status": "new", "path": manifest_path}
        
        # Create new entry for comparison
        new_entry = self.add_manifest(manifest_path, manifest)
        
        if new_entry.digest == entry.digest:
            return {"status": "unchanged", "path": manifest_path}
        
        # Analyze changes
        changes = {
            "status": "modified",
            "path": manifest_path,
            "old_digest": entry.digest,
            "new_digest": new_entry.digest,
            "old_version": entry.version,
            "new_version": new_entry.version,
            "tool_changes": []
        }
        
        # Compare tools
        old_tools = set(entry.tools.keys())
        new_tools = set(new_entry.tools.keys())
        
        # Added tools
        for tool in new_tools - old_tools:
            changes["tool_changes"].append({
                "type": "added",
                "name": tool,
                "digest": new_entry.tools[tool]
            })
        
        # Removed tools
        for tool in old_tools - new_tools:
            changes["tool_changes"].append({
                "type": "removed",
                "name": tool,
                "digest": entry.tools[tool]
            })
        
        # Modified tools
        for tool in old_tools & new_tools:
            if entry.tools[tool] != new_entry.tools[tool]:
                changes["tool_changes"].append({
                    "type": "modified",
                    "name": tool,
                    "old_digest": entry.tools[tool],
                    "new_digest": new_entry.tools[tool]
                })
        
        return changes
    
    def list_entries(self) -> List[LockEntry]:
        """List all lock entries."""
        return list(self._entries.values())
    
    def remove_entry(self, manifest_path: str) -> bool:
        """Remove an entry from the lock file."""
        if manifest_path in self._entries:
            del self._entries[manifest_path]
            return True
        return False
    
    def update_signature(self, manifest_path: str, signature: Dict[str, Any]) -> bool:
        """Update the signature for an entry."""
        entry = self.get_entry(manifest_path)
        if entry:
            entry.signature = signature
            return True
        return False
    
    def export_for_ci(self) -> Dict[str, str]:
        """
        Export simplified digest map for CI verification.
        
        Returns:
            Dictionary of path -> digest for easy CI checking
        """
        return {
            path: entry.digest
            for path, entry in self._entries.items()
        }
    
    def import_from_ci(self, digest_map: Dict[str, str]) -> None:
        """
        Import digest map from CI.
        
        This creates basic entries without full metadata.
        """
        for path, digest in digest_map.items():
            if path not in self._entries:
                self._entries[path] = LockEntry(
                    path=path,
                    digest=digest
                )