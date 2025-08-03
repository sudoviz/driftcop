"""Integration tests for CLI functionality."""

import json
import pytest
from pathlib import Path
from typer.testing import CliRunner
from mcp_sec.cli import app


class TestCLIIntegration:
    """Test CLI integration and workflows."""
    
    @pytest.fixture
    def runner(self):
        """Create a CLI test runner."""
        return CliRunner()
    
    @pytest.fixture
    def test_project(self, tmp_path):
        """Create a test project structure."""
        # Create manifest
        manifest_data = {
            "name": "integration-test-server",
            "version": "1.0.0",
            "description": "Integration test MCP server",
            "tools": [
                {
                    "name": "calculator",
                    "description": "Perform calculations",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "expression": {"type": "string"}
                        },
                        "required": ["expression"]
                    }
                },
                {
                    "name": "file_reader",
                    "description": "Read files from disk",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"}
                        },
                        "required": ["path"]
                    }
                }
            ]
        }
        
        manifest_file = tmp_path / "mcp.json"
        manifest_file.write_text(json.dumps(manifest_data, indent=2))
        
        # Create source files
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        
        # Python file with tool definitions
        python_file = src_dir / "tools.py"
        python_file.write_text('''
from mcp import register_tool

register_tool(
    name="calculator",
    description="Perform calculations",
    input_schema={"type": "object", "properties": {"expression": {"type": "string"}}}
)

register_tool(
    name="file_reader", 
    description="Read files from disk",
    input_schema={"type": "object", "properties": {"path": {"type": "string"}}}
)

def unsafe_code(user_input):
    # This should trigger a warning
    return eval(user_input)
''')
        
        # Package.json for dependencies
        package_json = tmp_path / "package.json"
        package_json.write_text(json.dumps({
            "name": "integration-test",
            "version": "1.0.0",
            "dependencies": {
                "@modelcontextprotocol/server": "1.0.0",
                "express": "4.17.1"
            }
        }, indent=2))
        
        return tmp_path
    
    def test_scan_command(self, runner, test_project):
        """Test the main scan command."""
        result = runner.invoke(app, ["scan", str(test_project)])
        
        assert result.exit_code == 0
        assert "MCP Security Scan Report" in result.output
        assert "integration-test-server" in result.output
        
        # Should detect the eval usage
        assert "eval" in result.output
        
        # Should show summary
        assert "Summary" in result.output
    
    def test_scan_with_manifest_path(self, runner, test_project):
        """Test scan with specific manifest path."""
        manifest_path = test_project / "mcp.json"
        result = runner.invoke(app, ["scan", str(test_project), "--manifest", str(manifest_path)])
        
        assert result.exit_code == 0
        assert "integration-test-server" in result.output
    
    def test_scan_with_json_output(self, runner, test_project):
        """Test scan with JSON output format."""
        result = runner.invoke(app, ["scan", str(test_project), "--format", "json"])
        
        assert result.exit_code == 0
        
        # Should be valid JSON
        output_data = json.loads(result.output)
        assert "summary" in output_data
        assert "findings" in output_data
        assert output_data["summary"]["total_scanners"] > 0
    
    def test_scan_with_output_file(self, runner, test_project, tmp_path):
        """Test scan with output file."""
        output_file = tmp_path / "report.json"
        
        result = runner.invoke(app, [
            "scan", str(test_project),
            "--format", "json",
            "--output", str(output_file)
        ])
        
        assert result.exit_code == 0
        assert output_file.exists()
        
        # Verify file content
        report_data = json.loads(output_file.read_text())
        assert "summary" in report_data
    
    def test_scan_specific_scanners(self, runner, test_project):
        """Test running specific scanners only."""
        result = runner.invoke(app, [
            "scan", str(test_project),
            "--scanners", "manifest,typosquatting"
        ])
        
        assert result.exit_code == 0
        output = result.output.lower()
        
        # Should run specified scanners
        assert "manifest" in output
        assert "typosquatting" in output
        
        # Should not run others
        assert "semantic" not in output or "skipped" in output
    
    def test_lock_add_command(self, runner, test_project):
        """Test adding manifest to lock file."""
        manifest_path = test_project / "mcp.json"
        lockfile_path = test_project / ".mcpsec-lock.toml"
        
        result = runner.invoke(app, [
            "lock", "add", str(manifest_path),
            "--lockfile", str(lockfile_path)
        ])
        
        assert result.exit_code == 0
        assert lockfile_path.exists()
        assert "Added manifest to lock file" in result.output
        
        # Verify lock file content
        import toml
        lock_data = toml.load(lockfile_path)
        assert len(lock_data["entries"]) == 1
        assert lock_data["entries"][0]["server_name"] == "integration-test-server"
    
    def test_lock_verify_command(self, runner, test_project):
        """Test verifying manifest against lock file."""
        manifest_path = test_project / "mcp.json"
        lockfile_path = test_project / ".mcpsec-lock.toml"
        
        # First add to lock file
        runner.invoke(app, [
            "lock", "add", str(manifest_path),
            "--lockfile", str(lockfile_path)
        ])
        
        # Then verify
        result = runner.invoke(app, [
            "lock", "verify", str(manifest_path),
            "--lockfile", str(lockfile_path)
        ])
        
        assert result.exit_code == 0
        assert "valid" in result.output.lower()
    
    def test_lock_verify_changed_manifest(self, runner, test_project):
        """Test verifying changed manifest."""
        manifest_path = test_project / "mcp.json"
        lockfile_path = test_project / ".mcpsec-lock.toml"
        
        # Add to lock file
        runner.invoke(app, [
            "lock", "add", str(manifest_path),
            "--lockfile", str(lockfile_path)
        ])
        
        # Modify manifest
        manifest_data = json.loads(manifest_path.read_text())
        manifest_data["version"] = "2.0.0"
        manifest_path.write_text(json.dumps(manifest_data))
        
        # Verify should fail
        result = runner.invoke(app, [
            "lock", "verify", str(manifest_path),
            "--lockfile", str(lockfile_path),
            "--strict"
        ])
        
        assert result.exit_code != 0
        assert "changed" in result.output.lower()
    
    def test_version_command(self, runner):
        """Test version command."""
        result = runner.invoke(app, ["--version"])
        
        assert result.exit_code == 0
        assert "mcp-sec version" in result.output
    
    def test_ci_mode(self, runner, test_project):
        """Test CI mode with strict checking."""
        # Add a file that will cause findings
        unsafe_file = test_project / "unsafe.py"
        unsafe_file.write_text('''
import os
os.system(user_input)  # Dangerous!
''')
        
        result = runner.invoke(app, [
            "scan", str(test_project),
            "--ci",
            "--format", "sarif"
        ])
        
        # Should exit with non-zero code due to findings
        assert result.exit_code != 0
        
        # Should output SARIF format
        sarif_data = json.loads(result.output)
        assert sarif_data["version"] == "2.1.0"
        assert len(sarif_data["runs"][0]["results"]) > 0
    
    def test_scan_with_config_file(self, runner, test_project):
        """Test scan with configuration file."""
        # Create config file
        config_file = test_project / ".mcp-sec.toml"
        config_file.write_text("""
[scanners]
enabled = ["manifest", "workspace", "typosquatting"]
disabled = ["semantic_drift"]

[scanners.workspace]
ignore_patterns = ["test_*", "*.test.js"]

[report]
format = "json"
""")
        
        result = runner.invoke(app, [
            "scan", str(test_project),
            "--config", str(config_file)
        ])
        
        assert result.exit_code == 0
        
        # Output should be JSON due to config
        output_data = json.loads(result.output)
        assert isinstance(output_data, dict)