"""Pytest configuration and shared fixtures."""

import os
import sys
import pytest
from pathlib import Path

# Add the src directory to Python path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))


@pytest.fixture
def temp_manifest(tmp_path):
    """Create a temporary manifest file."""
    import json
    
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
                    }
                }
            }
        ]
    }
    
    manifest_file = tmp_path / "mcp.json"
    manifest_file.write_text(json.dumps(manifest_data, indent=2))
    return manifest_file


@pytest.fixture
def mock_openai_key(monkeypatch):
    """Mock OpenAI API key for tests."""
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-12345")


@pytest.fixture
def sample_lockfile(tmp_path):
    """Create a sample lock file."""
    lockfile_content = """
version = "1.0"

[[entries]]
manifest_path = "/test/mcp.json"
manifest_digest = "abc123def456"
server_name = "test-server"
version = "1.0.0"
approved_at = "2024-01-01T00:00:00Z"

[entries.tool_digests]
test_tool = "tool123digest"
"""
    
    lockfile = tmp_path / ".mcpsec-lock.toml"
    lockfile.write_text(lockfile_content)
    return lockfile


@pytest.fixture(autouse=True)
def reset_environment(monkeypatch):
    """Reset environment variables for each test."""
    # Clear any existing API keys
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    
    # Set test mode
    monkeypatch.setenv("MCP_SEC_TEST_MODE", "true")