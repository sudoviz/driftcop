"""Dependency scanner for checking package vulnerabilities."""

import json
import re
from pathlib import Path
from typing import List, Dict, Any

from mcp_sec.models import ScanResult, Finding, FindingSeverity, FindingCategory


class DependencyScanner:
    """Scanner for dependency vulnerabilities and issues."""
    
    # Known vulnerable package versions (simplified for demo)
    KNOWN_VULNERABILITIES = {
        "lodash": {"<4.17.21": "Prototype pollution vulnerability"},
        "minimist": {"<1.2.6": "Prototype pollution vulnerability"},
        "axios": {"<0.21.2": "SSRF vulnerability"},
        "node-fetch": {"<2.6.7": "Regular expression DoS"},
        "django": {"<2.2.28": "SQL injection vulnerability"},
        "flask": {"<2.2.5": "Security vulnerability"},
        "pyyaml": {"<5.4": "Arbitrary code execution"},
        "urllib3": {"<1.26.5": "Security vulnerability"},
    }
    
    # MCP-related package patterns
    MCP_PACKAGE_PATTERNS = [
        r"@modelcontextprotocol/",
        r"mcp-.*",
        r".*-mcp$",
        r"modelcontextprotocol"
    ]
    
    def scan(self, directory_path: str) -> ScanResult:
        """Scan a directory for dependency files and check for vulnerabilities."""
        findings = []
        metadata = {
            "directory": directory_path,
            "package_managers": [],
            "total_dependencies": 0,
            "mcp_dependencies": []
        }
        
        directory = Path(directory_path)
        if not directory.exists():
            findings.append(Finding(
                severity=FindingSeverity.ERROR,
                category=FindingCategory.CONFIGURATION,
                title="Directory not found",
                description=f"The directory '{directory_path}' does not exist",
                recommendation="Provide a valid directory path"
            ))
            return ScanResult(
                scanner_name="dependencies",
                passed=False,
                findings=findings,
                metadata=metadata
            )
        
        # Check for package.json (npm/yarn)
        package_json = directory / "package.json"
        if package_json.exists():
            npm_findings, npm_packages = self._scan_package_json(package_json)
            findings.extend(npm_findings)
            metadata["package_managers"].append("npm")
            metadata["total_dependencies"] += len(npm_packages)
            
            # Find MCP packages
            mcp_packages = [p for p in npm_packages if self._is_mcp_package(p["name"])]
            metadata["mcp_dependencies"].extend(p["name"] for p in mcp_packages)
        
        # Check for requirements.txt (pip)
        requirements_txt = directory / "requirements.txt"
        if requirements_txt.exists():
            pip_findings, pip_packages = self._scan_requirements_txt(requirements_txt)
            findings.extend(pip_findings)
            metadata["package_managers"].append("pip")
            metadata["total_dependencies"] += len(pip_packages)
            
            # Find MCP packages
            mcp_packages = [p for p in pip_packages if self._is_mcp_package(p["name"])]
            metadata["mcp_dependencies"].extend(p["name"] for p in mcp_packages)
        
        # Check for pyproject.toml (poetry)
        pyproject_toml = directory / "pyproject.toml"
        if pyproject_toml.exists():
            poetry_findings, poetry_packages = self._scan_pyproject_toml(pyproject_toml)
            findings.extend(poetry_findings)
            metadata["package_managers"].append("poetry")
            metadata["total_dependencies"] += len(poetry_packages)
            
            # Find MCP packages
            mcp_packages = [p for p in poetry_packages if self._is_mcp_package(p["name"])]
            metadata["mcp_dependencies"].extend(p["name"] for p in mcp_packages)
        
        return ScanResult(
            scanner_name="dependencies",
            passed=len(findings) == 0,
            findings=findings,
            metadata=metadata
        )
    
    def _scan_package_json(self, package_json_path: Path) -> tuple[List[Finding], List[Dict[str, Any]]]:
        """Scan package.json for vulnerabilities."""
        findings = []
        packages = []
        
        try:
            with open(package_json_path) as f:
                data = json.load(f)
            
            # Parse dependencies
            all_packages = self._parse_package_json(data)
            packages.extend(all_packages)
            
            # Check for vulnerabilities
            for package in all_packages:
                vuln_findings = self._check_vulnerability(package)
                findings.extend(vuln_findings)
            
            # Check for outdated packages
            outdated_findings = self._check_outdated_packages(all_packages)
            findings.extend(outdated_findings)
            
        except Exception as e:
            findings.append(Finding(
                severity=FindingSeverity.ERROR,
                category=FindingCategory.INTERNAL_ERROR,
                title="Failed to parse package.json",
                description=f"Error parsing package.json: {str(e)}",
                recommendation="Fix the package.json syntax"
            ))
        
        return findings, packages
    
    def _scan_requirements_txt(self, requirements_path: Path) -> tuple[List[Finding], List[Dict[str, Any]]]:
        """Scan requirements.txt for vulnerabilities."""
        findings = []
        packages = []
        
        try:
            packages = self._parse_requirements_txt(requirements_path)
            
            # Check for vulnerabilities
            for package in packages:
                vuln_findings = self._check_vulnerability(package)
                findings.extend(vuln_findings)
            
        except Exception as e:
            findings.append(Finding(
                severity=FindingSeverity.ERROR,
                category=FindingCategory.INTERNAL_ERROR,
                title="Failed to parse requirements.txt",
                description=f"Error parsing requirements.txt: {str(e)}",
                recommendation="Fix the requirements.txt format"
            ))
        
        return findings, packages
    
    def _scan_pyproject_toml(self, pyproject_path: Path) -> tuple[List[Finding], List[Dict[str, Any]]]:
        """Scan pyproject.toml for vulnerabilities."""
        findings = []
        packages = []
        
        try:
            import toml
            with open(pyproject_path) as f:
                data = toml.load(f)
            
            packages = self._parse_pyproject_toml(data)
            
            # Check for vulnerabilities
            for package in packages:
                vuln_findings = self._check_vulnerability(package)
                findings.extend(vuln_findings)
            
        except Exception as e:
            findings.append(Finding(
                severity=FindingSeverity.ERROR,
                category=FindingCategory.INTERNAL_ERROR,
                title="Failed to parse pyproject.toml",
                description=f"Error parsing pyproject.toml: {str(e)}",
                recommendation="Fix the pyproject.toml format"
            ))
        
        return findings, packages
    
    def _parse_package_json(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse package.json and extract package information."""
        packages = []
        
        # Parse regular dependencies
        for name, version in data.get("dependencies", {}).items():
            packages.append({
                "name": name,
                "version": self._clean_version(version),
                "type": "production"
            })
        
        # Parse dev dependencies
        for name, version in data.get("devDependencies", {}).items():
            packages.append({
                "name": name,
                "version": self._clean_version(version),
                "type": "development"
            })
        
        return packages
    
    def _parse_requirements_txt(self, requirements_path: Path) -> List[Dict[str, Any]]:
        """Parse requirements.txt and extract package information."""
        packages = []
        
        with open(requirements_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Parse package==version format
                match = re.match(r'^([a-zA-Z0-9._-]+)\s*([><=!~]+)\s*(.+)$', line)
                if match:
                    name, op, version = match.groups()
                    packages.append({
                        "name": name.lower(),
                        "version": version,
                        "type": "production"
                    })
        
        return packages
    
    def _parse_pyproject_toml(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse pyproject.toml and extract package information."""
        packages = []
        
        # Poetry dependencies
        poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        for name, version in poetry_deps.items():
            if name == "python":
                continue
            packages.append({
                "name": name,
                "version": self._clean_version(str(version)),
                "type": "production"
            })
        
        # Poetry dev dependencies
        poetry_dev_deps = data.get("tool", {}).get("poetry", {}).get("dev-dependencies", {})
        for name, version in poetry_dev_deps.items():
            packages.append({
                "name": name,
                "version": self._clean_version(str(version)),
                "type": "development"
            })
        
        return packages
    
    def _check_vulnerability(self, package: Dict[str, Any]) -> List[Finding]:
        """Check if a package has known vulnerabilities."""
        findings = []
        
        name = package["name"].lower()
        version = package["version"]
        
        if name in self.KNOWN_VULNERABILITIES:
            for vulnerable_version, description in self.KNOWN_VULNERABILITIES[name].items():
                if self._is_vulnerable_version(version, vulnerable_version):
                    findings.append(Finding(
                        severity=FindingSeverity.HIGH,
                        category=FindingCategory.DEPENDENCY_VULN,
                        title=f"Vulnerable dependency: {name}",
                        description=f"{name} {version} has a known vulnerability: {description}",
                        recommendation=f"Update {name} to the latest version",
                        metadata={
                            "package": name,
                            "current_version": version,
                            "vulnerability": description
                        }
                    ))
        
        return findings
    
    def _check_outdated_packages(self, packages: List[Dict[str, Any]]) -> List[Finding]:
        """Check for potentially outdated packages."""
        findings = []
        
        # Simple heuristic: warn about very old major versions
        for package in packages:
            name = package["name"]
            version = package["version"]
            
            # Check if it's a very old version (e.g., 0.x.x or 1.x.x for mature packages)
            if re.match(r'^[01]\.', version) and name in ["lodash", "express", "axios"]:
                findings.append(Finding(
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.CONFIGURATION,
                    title=f"Potentially outdated package: {name}",
                    description=f"{name} {version} appears to be an old version",
                    recommendation=f"Consider updating {name} to the latest stable version",
                    metadata={
                        "package": name,
                        "current_version": version
                    }
                ))
        
        return findings
    
    def _is_mcp_package(self, package_name: str) -> bool:
        """Check if a package is MCP-related."""
        for pattern in self.MCP_PACKAGE_PATTERNS:
            if re.match(pattern, package_name, re.IGNORECASE):
                return True
        return False
    
    def _clean_version(self, version: str) -> str:
        """Clean version string to remove prefixes."""
        return re.sub(r'^[~^>=<]+', '', version)
    
    def _is_vulnerable_version(self, current: str, vulnerable_spec: str) -> bool:
        """Check if current version matches vulnerable specification."""
        # Simple implementation - just check if it starts with < and compare
        if vulnerable_spec.startswith("<"):
            threshold = vulnerable_spec[1:]
            return self._compare_versions(current, threshold) < 0
        return False
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """Simple version comparison."""
        # Very basic implementation
        try:
            parts1 = [int(x) for x in v1.split('.')]
            parts2 = [int(x) for x in v2.split('.')]
            
            for i in range(max(len(parts1), len(parts2))):
                p1 = parts1[i] if i < len(parts1) else 0
                p2 = parts2[i] if i < len(parts2) else 0
                
                if p1 < p2:
                    return -1
                elif p1 > p2:
                    return 1
            
            return 0
        except:
            return 0