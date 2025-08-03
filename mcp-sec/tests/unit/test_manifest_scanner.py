"""Unit tests for manifest scanner."""

import json
import pytest
from pathlib import Path
from mcp_sec.scanners.manifest import ManifestScanner
from mcp_sec.models import MCPManifest, MCPTool, ScanResult, FindingSeverity


class TestManifestScanner:
    """Test manifest scanner functionality."""
    
    @pytest.fixture
    def scanner(self):
        """Create a manifest scanner instance."""
        return ManifestScanner()
    
    @pytest.fixture
    def valid_manifest(self, tmp_path):
        """Create a valid manifest file."""
        manifest_data = {
            "name": "test-server",
            "version": "1.0.0",
            "description": "Test MCP server",
            "tools": [
                {
                    "name": "test_tool",
                    "description": "A test tool",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "input": {"type": "string"}
                        },
                        "required": ["input"]
                    }
                }
            ]
        }
        manifest_path = tmp_path / "mcp.json"
        manifest_path.write_text(json.dumps(manifest_data))
        return manifest_path
    
    @pytest.fixture
    def invalid_manifest(self, tmp_path):
        """Create an invalid manifest file."""
        manifest_data = {
            "name": "test-server",
            # Missing required version field
            "tools": "not-an-array"  # Invalid type
        }
        manifest_path = tmp_path / "invalid.json"
        manifest_path.write_text(json.dumps(manifest_data))
        return manifest_path
    
    def test_scan_valid_manifest(self, scanner, valid_manifest):
        """Test scanning a valid manifest."""
        result = scanner.scan(str(valid_manifest))
        
        assert result.passed
        assert len(result.findings) == 0
        assert result.metadata["manifest_path"] == str(valid_manifest)
        assert result.metadata["server_name"] == "test-server"
        assert result.metadata["server_version"] == "1.0.0"
        assert result.metadata["tool_count"] == 1
    
    def test_scan_invalid_manifest(self, scanner, invalid_manifest):
        """Test scanning an invalid manifest."""
        result = scanner.scan(str(invalid_manifest))
        
        assert not result.passed
        assert len(result.findings) > 0
        
        # Check for schema validation errors
        schema_findings = [f for f in result.findings if "schema" in f.title.lower()]
        assert len(schema_findings) > 0
    
    def test_scan_missing_file(self, scanner):
        """Test scanning a non-existent file."""
        result = scanner.scan("/path/to/nonexistent.json")
        
        assert not result.passed
        assert len(result.findings) > 0
        assert any("not found" in f.description.lower() for f in result.findings)
    
    def test_check_dangerous_tool_names(self, scanner, tmp_path):
        """Test detection of dangerous tool names."""
        manifest_data = {
            "name": "test-server",
            "version": "1.0.0",
            "tools": [
                {
                    "name": "execute_command",  # Dangerous name
                    "description": "Execute system commands",
                    "inputSchema": {"type": "object"}
                },
                {
                    "name": "safe_tool",
                    "description": "A safe tool",
                    "inputSchema": {"type": "object"}
                }
            ]
        }
        manifest_path = tmp_path / "dangerous.json"
        manifest_path.write_text(json.dumps(manifest_data))
        
        result = scanner.scan(str(manifest_path))
        
        # Should have warning about dangerous tool name
        dangerous_findings = [f for f in result.findings if "dangerous" in f.title.lower()]
        assert len(dangerous_findings) > 0
        assert dangerous_findings[0].severity == FindingSeverity.WARNING
    
    def test_check_overly_broad_permissions(self, scanner, tmp_path):
        """Test detection of overly broad permissions."""
        manifest_data = {
            "name": "test-server",
            "version": "1.0.0",
            "tools": [
                {
                    "name": "test_tool",
                    "description": "A test tool",
                    "inputSchema": {
                        "type": "object",
                        "additionalProperties": True  # Too permissive
                    }
                }
            ]
        }
        manifest_path = tmp_path / "broad.json"
        manifest_path.write_text(json.dumps(manifest_data))
        
        result = scanner.scan(str(manifest_path))
        
        # Should have warning about broad permissions
        broad_findings = [f for f in result.findings if "broad" in f.title.lower() or "permissive" in f.title.lower()]
        assert len(broad_findings) > 0
    
    def test_parse_manifest(self, scanner, valid_manifest):
        """Test manifest parsing."""
        with open(valid_manifest) as f:
            data = json.load(f)
        
        manifest = scanner._parse_manifest(data, str(valid_manifest))
        
        assert isinstance(manifest, MCPManifest)
        assert manifest.name == "test-server"
        assert manifest.version == "1.0.0"
        assert len(manifest.tools) == 1
        assert isinstance(manifest.tools[0], MCPTool)