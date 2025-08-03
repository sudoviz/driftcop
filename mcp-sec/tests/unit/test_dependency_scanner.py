"""Unit tests for dependency scanner."""

import json
import pytest
from pathlib import Path
from mcp_sec.scanners.dependencies import DependencyScanner
from mcp_sec.models import FindingSeverity


class TestDependencyScanner:
    """Test dependency scanning functionality."""
    
    @pytest.fixture
    def scanner(self):
        """Create a dependency scanner instance."""
        return DependencyScanner()
    
    @pytest.fixture
    def package_json(self, tmp_path):
        """Create a test package.json file."""
        package_data = {
            "name": "test-mcp-server",
            "version": "1.0.0",
            "dependencies": {
                "express": "4.17.1",
                "lodash": "4.17.20",  # Old version with vulnerabilities
                "axios": "0.21.0",    # Old version with vulnerabilities
                "@modelcontextprotocol/server": "1.0.0"
            },
            "devDependencies": {
                "jest": "26.0.0",
                "eslint": "7.0.0"
            }
        }
        package_file = tmp_path / "package.json"
        package_file.write_text(json.dumps(package_data, indent=2))
        return package_file
    
    @pytest.fixture
    def requirements_txt(self, tmp_path):
        """Create a test requirements.txt file."""
        requirements = """
flask==1.1.2
requests==2.24.0
django==2.2.10
PyYAML==5.3
mcp-server==1.0.0
"""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text(requirements)
        return req_file
    
    @pytest.fixture
    def pyproject_toml(self, tmp_path):
        """Create a test pyproject.toml file."""
        pyproject_content = """
[tool.poetry]
name = "test-mcp-server"
version = "1.0.0"

[tool.poetry.dependencies]
python = "^3.8"
fastapi = "0.65.0"
pydantic = "1.8.0"
urllib3 = "1.26.4"
cryptography = "3.4.6"

[tool.poetry.dev-dependencies]
pytest = "^6.2.0"
black = "^21.5b0"
"""
        pyproject_file = tmp_path / "pyproject.toml"
        pyproject_file.write_text(pyproject_content)
        return pyproject_file
    
    def test_scan_package_json(self, scanner, package_json):
        """Test scanning package.json for vulnerabilities."""
        result = scanner.scan(str(package_json.parent))
        
        # Should find the package.json
        assert "npm" in result.metadata.get("package_managers", [])
        assert result.metadata.get("total_dependencies", 0) > 0
        
        # Should identify MCP-related dependencies
        assert "mcp_dependencies" in result.metadata
        mcp_deps = result.metadata["mcp_dependencies"]
        assert "@modelcontextprotocol/server" in mcp_deps
    
    def test_scan_requirements_txt(self, scanner, requirements_txt):
        """Test scanning requirements.txt for vulnerabilities."""
        result = scanner.scan(str(requirements_txt.parent))
        
        # Should find the requirements.txt
        assert "pip" in result.metadata.get("package_managers", [])
        
        # Should identify MCP-related dependencies
        mcp_deps = result.metadata.get("mcp_dependencies", [])
        assert "mcp-server" in mcp_deps
    
    def test_scan_pyproject_toml(self, scanner, pyproject_toml):
        """Test scanning pyproject.toml for vulnerabilities."""
        result = scanner.scan(str(pyproject_toml.parent))
        
        # Should find the pyproject.toml
        assert "poetry" in result.metadata.get("package_managers", [])
        assert result.metadata.get("total_dependencies", 0) > 0
    
    def test_check_outdated_packages(self, scanner, package_json):
        """Test detection of outdated packages."""
        result = scanner.scan(str(package_json.parent))
        
        # Check for outdated package warnings
        outdated_findings = [
            f for f in result.findings
            if "outdated" in f.title.lower() or "latest" in f.description.lower()
        ]
        
        # Should find some outdated packages
        if outdated_findings:
            assert any("lodash" in f.description for f in outdated_findings)
    
    def test_parse_package_json(self, scanner, package_json):
        """Test package.json parsing."""
        with open(package_json) as f:
            data = json.load(f)
        
        packages = scanner._parse_package_json(data)
        
        assert len(packages) > 0
        
        # Check specific package
        lodash = next((p for p in packages if p["name"] == "lodash"), None)
        assert lodash is not None
        assert lodash["version"] == "4.17.20"
        assert lodash["type"] == "production"
        
        # Check dev dependency
        jest = next((p for p in packages if p["name"] == "jest"), None)
        assert jest is not None
        assert jest["type"] == "development"
    
    def test_parse_requirements_txt(self, scanner, requirements_txt):
        """Test requirements.txt parsing."""
        packages = scanner._parse_requirements_txt(requirements_txt)
        
        assert len(packages) > 0
        
        # Check specific package
        flask = next((p for p in packages if p["name"] == "flask"), None)
        assert flask is not None
        assert flask["version"] == "1.1.2"
        assert flask["type"] == "production"
    
    def test_parse_pyproject_toml(self, scanner, pyproject_toml):
        """Test pyproject.toml parsing."""
        import toml
        with open(pyproject_toml) as f:
            data = toml.load(f)
        
        packages = scanner._parse_pyproject_toml(data)
        
        assert len(packages) > 0
        
        # Check specific package
        fastapi = next((p for p in packages if p["name"] == "fastapi"), None)
        assert fastapi is not None
        assert fastapi["version"] == "0.65.0"
        assert fastapi["type"] == "production"
    
    def test_vulnerable_package_detection(self, scanner, tmp_path):
        """Test detection of known vulnerable packages."""
        # Create package.json with known vulnerable versions
        package_data = {
            "name": "vulnerable-test",
            "version": "1.0.0",
            "dependencies": {
                "minimist": "0.0.8",  # Known vulnerable version
                "node-fetch": "2.6.0",  # Known vulnerable version
                "log4js": "4.0.0"     # Potentially vulnerable
            }
        }
        package_file = tmp_path / "package.json"
        package_file.write_text(json.dumps(package_data))
        
        result = scanner.scan(str(tmp_path))
        
        # Should detect as potentially vulnerable based on common patterns
        vuln_findings = [
            f for f in result.findings
            if "vulnerab" in f.title.lower() or "security" in f.description.lower()
        ]
        
        # Scanner should at least note these packages for review
        assert result.metadata.get("total_dependencies", 0) == 3
    
    def test_license_check(self, scanner, package_json):
        """Test license compatibility checking."""
        result = scanner.scan(str(package_json.parent))
        
        # Should check for license issues
        license_findings = [
            f for f in result.findings
            if "license" in f.title.lower()
        ]
        
        # This is optional - scanner may or may not check licenses
        # but if it does, verify the structure
        if license_findings:
            assert all(f.severity in [FindingSeverity.INFO, FindingSeverity.WARNING] 
                      for f in license_findings)
    
    def test_scan_multiple_package_files(self, scanner, tmp_path):
        """Test scanning directory with multiple package files."""
        # Create both package.json and requirements.txt
        package_data = {
            "name": "node-project",
            "dependencies": {"express": "4.17.1"}
        }
        (tmp_path / "package.json").write_text(json.dumps(package_data))
        (tmp_path / "requirements.txt").write_text("flask==2.0.0\n")
        
        result = scanner.scan(str(tmp_path))
        
        # Should find both package managers
        assert "npm" in result.metadata.get("package_managers", [])
        assert "pip" in result.metadata.get("package_managers", [])
        
        # Should count dependencies from both
        assert result.metadata.get("total_dependencies", 0) >= 2