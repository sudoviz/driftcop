"""Unit tests for lock file management."""

import json
import pytest
from pathlib import Path
from datetime import datetime
from mcp_sec.lockfile.manager import LockFileManager
from mcp_sec.lockfile.models import LockFileEntry, ToolDigest
from mcp_sec.models import MCPManifest, MCPTool


class TestLockFileManager:
    """Test lock file management functionality."""
    
    @pytest.fixture
    def manager(self, tmp_path):
        """Create a lock file manager instance."""
        lockfile_path = tmp_path / ".mcpsec-lock.toml"
        return LockFileManager(lockfile_path)
    
    @pytest.fixture
    def sample_manifest(self, tmp_path):
        """Create a sample manifest."""
        manifest_data = {
            "name": "test-server",
            "version": "1.0.0",
            "description": "Test server",
            "tools": [
                {
                    "name": "tool1",
                    "description": "First tool",
                    "inputSchema": {"type": "object"}
                },
                {
                    "name": "tool2", 
                    "description": "Second tool",
                    "inputSchema": {"type": "object"}
                }
            ]
        }
        manifest_path = tmp_path / "mcp.json"
        manifest_path.write_text(json.dumps(manifest_data))
        return manifest_path
    
    def test_add_manifest(self, manager, sample_manifest):
        """Test adding a manifest to lock file."""
        entry = manager.add_manifest(str(sample_manifest))
        
        assert entry is not None
        assert entry.manifest_path == str(sample_manifest)
        assert entry.manifest_digest is not None
        assert len(entry.tool_digests) == 2
        assert entry.tool_digests["tool1"] is not None
        assert entry.tool_digests["tool2"] is not None
        assert entry.approved_at is not None
        
        # Verify lock file was written
        assert manager.lockfile_path.exists()
    
    def test_verify_manifest_unchanged(self, manager, sample_manifest):
        """Test verifying an unchanged manifest."""
        # Add manifest
        entry = manager.add_manifest(str(sample_manifest))
        
        # Verify it hasn't changed
        is_valid = manager.verify_manifest(str(sample_manifest))
        assert is_valid
    
    def test_verify_manifest_changed(self, manager, sample_manifest):
        """Test detecting manifest changes."""
        # Add manifest
        manager.add_manifest(str(sample_manifest))
        
        # Modify manifest
        manifest_data = json.loads(sample_manifest.read_text())
        manifest_data["tools"][0]["description"] = "Modified description"
        sample_manifest.write_text(json.dumps(manifest_data))
        
        # Should detect change
        is_valid = manager.verify_manifest(str(sample_manifest))
        assert not is_valid
    
    def test_update_manifest(self, manager, sample_manifest):
        """Test updating a manifest entry."""
        # Add manifest
        original_entry = manager.add_manifest(str(sample_manifest))
        original_digest = original_entry.manifest_digest
        
        # Modify manifest
        manifest_data = json.loads(sample_manifest.read_text())
        manifest_data["version"] = "2.0.0"
        sample_manifest.write_text(json.dumps(manifest_data))
        
        # Update entry
        updated_entry = manager.update_manifest(str(sample_manifest))
        
        assert updated_entry is not None
        assert updated_entry.manifest_digest != original_digest
        assert updated_entry.version == "2.0.0"
        assert updated_entry.approved_at > original_entry.approved_at
    
    def test_remove_manifest(self, manager, sample_manifest):
        """Test removing a manifest from lock file."""
        # Add manifest
        manager.add_manifest(str(sample_manifest))
        
        # Remove it
        removed = manager.remove_manifest(str(sample_manifest))
        assert removed
        
        # Verify it's gone
        entries = manager.list_entries()
        assert len(entries) == 0
    
    def test_list_entries(self, manager, tmp_path):
        """Test listing lock file entries."""
        # Add multiple manifests
        manifest1 = tmp_path / "mcp1.json"
        manifest1.write_text('{"name": "server1", "version": "1.0.0", "tools": []}')
        
        manifest2 = tmp_path / "mcp2.json"
        manifest2.write_text('{"name": "server2", "version": "1.0.0", "tools": []}')
        
        manager.add_manifest(str(manifest1))
        manager.add_manifest(str(manifest2))
        
        entries = manager.list_entries()
        assert len(entries) == 2
        assert any(e.manifest_path == str(manifest1) for e in entries)
        assert any(e.manifest_path == str(manifest2) for e in entries)
    
    def test_get_changes(self, manager, sample_manifest):
        """Test detecting specific changes in manifest."""
        # Add manifest
        manager.add_manifest(str(sample_manifest))
        
        # No changes initially
        changes = manager.get_changes(str(sample_manifest))
        assert changes is None
        
        # Modify a tool
        manifest_data = json.loads(sample_manifest.read_text())
        manifest_data["tools"][0]["description"] = "Updated description"
        sample_manifest.write_text(json.dumps(manifest_data))
        
        # Get changes
        changes = manager.get_changes(str(sample_manifest))
        assert changes is not None
        assert changes["manifest_changed"]
        assert "tool1" in changes["tools_changed"]
        assert "tool2" not in changes["tools_changed"]
    
    def test_signature_integration(self, manager, sample_manifest):
        """Test signature storage in lock file."""
        # Add manifest with signature
        entry = manager.add_manifest(
            str(sample_manifest),
            signature="dummy-signature-data"
        )
        
        assert entry.signature == "dummy-signature-data"
        
        # Verify signature is persisted
        loaded_entry = manager.get_entry(str(sample_manifest))
        assert loaded_entry.signature == "dummy-signature-data"
    
    def test_lock_file_format(self, manager, sample_manifest):
        """Test the TOML lock file format."""
        manager.add_manifest(str(sample_manifest))
        
        # Read and verify TOML structure
        import toml
        lock_data = toml.load(manager.lockfile_path)
        
        assert "version" in lock_data
        assert "entries" in lock_data
        assert len(lock_data["entries"]) == 1
        
        entry_data = lock_data["entries"][0]
        assert "manifest_path" in entry_data
        assert "manifest_digest" in entry_data
        assert "tool_digests" in entry_data
        assert "approved_at" in entry_data
    
    def test_concurrent_access(self, manager, sample_manifest):
        """Test handling concurrent access to lock file."""
        # This is a basic test - real concurrent testing would use threading
        manager.add_manifest(str(sample_manifest))
        
        # Create second manager instance
        manager2 = LockFileManager(manager.lockfile_path)
        
        # Both should see the same entries
        entries1 = manager.list_entries()
        entries2 = manager2.list_entries()
        
        assert len(entries1) == len(entries2)
        assert entries1[0].manifest_digest == entries2[0].manifest_digest