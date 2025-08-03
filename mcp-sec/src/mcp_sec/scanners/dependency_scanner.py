"""Scanner for dependency security issues."""

import json
import uuid
from pathlib import Path
from typing import List, Dict, Any

from mcp_sec.models import ScanResult, Finding, FindingType, Severity


# Mock CVE database - in production, this would query a real CVE API
KNOWN_CVES = {
    "mcp-server-filesystem@0.1.0": [
        {
            "cve": "CVE-2024-0001",
            "severity": "high",
            "description": "Path traversal vulnerability allows reading arbitrary files"
        }
    ],
    "typosquatted-pkg@1.0.0": [
        {
            "cve": "TYPO-001",
            "severity": "critical",
            "description": "This is a known typosquatted package"
        }
    ]
}

# Popular package names for typo detection
POPULAR_PACKAGES = {
    "react", "vue", "angular", "express", "lodash", "axios", "moment",
    "webpack", "babel", "typescript", "jest", "prettier", "eslint",
    "numpy", "pandas", "requests", "flask", "django", "pytest",
    "mcp-server", "mcp-client", "mcp-protocol"
}


def scan(path: Path, verbose: bool = False) -> ScanResult:
    """Scan project dependencies for security issues."""
    findings = []
    
    # Check for different dependency files
    dependency_files = {
        "package.json": _scan_npm_deps,
        "package-lock.json": _scan_npm_lock,
        "requirements.txt": _scan_python_deps,
        "Pipfile.lock": _scan_pipfile_lock,
        "go.mod": _scan_go_deps,
        "Cargo.toml": _scan_cargo_deps
    }
    
    for filename, scanner_func in dependency_files.items():
        dep_file = path / filename
        if dep_file.exists():
            try:
                file_findings = scanner_func(dep_file)
                findings.extend(file_findings)
            except Exception as e:
                if verbose:
                    print(f"Error scanning {filename}: {e}")
    
    # Calculate risk score
    total_risk = _calculate_risk_score(findings)
    
    return ScanResult(
        workspace_path=str(path),
        findings=findings,
        total_risk_score=total_risk
    )


def _scan_npm_deps(package_file: Path) -> List[Finding]:
    """Scan package.json for issues."""
    findings = []
    
    try:
        data = json.loads(package_file.read_text())
        
        all_deps = {}
        if "dependencies" in data:
            all_deps.update(data["dependencies"])
        if "devDependencies" in data:
            all_deps.update(data["devDependencies"])
        
        for package, version in all_deps.items():
            # Check for typosquatting
            typo_findings = _check_typosquatting(package, str(package_file))
            findings.extend(typo_findings)
            
            # Check for known CVEs
            cve_findings = _check_cves(package, version, str(package_file))
            findings.extend(cve_findings)
            
            # Check for suspicious version patterns
            if version == "*" or version == "latest":
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    type=FindingType.DEPENDENCY_VULN,
                    severity=Severity.MEDIUM,
                    title=f"Unpinned dependency: {package}",
                    description=f"Package '{package}' uses unpinned version '{version}'",
                    file_path=str(package_file),
                    cwe_id="CWE-1104",
                    fix_suggestion="Pin to a specific version for reproducible builds",
                    metadata={"package": package, "version": version}
                ))
            
            # Check for git dependencies (potential supply chain risk)
            if version.startswith("git") or "github.com" in version:
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    type=FindingType.DEPENDENCY_VULN,
                    severity=Severity.MEDIUM,
                    title=f"Git dependency: {package}",
                    description="Using git URLs for dependencies can be a supply chain risk",
                    file_path=str(package_file),
                    cwe_id="CWE-494",
                    fix_suggestion="Use published package versions from npm registry",
                    metadata={"package": package, "version": version}
                ))
    
    except Exception as e:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            type=FindingType.SCHEMA_VIOLATION,
            severity=Severity.LOW,
            title="Failed to parse package.json",
            description=str(e),
            file_path=str(package_file),
            cwe_id="CWE-20"
        ))
    
    return findings


def _scan_npm_lock(lock_file: Path) -> List[Finding]:
    """Scan package-lock.json for integrity issues."""
    findings = []
    
    try:
        data = json.loads(lock_file.read_text())
        
        # Check for packages without integrity hashes
        if "packages" in data:
            for path, info in data["packages"].items():
                if path and "integrity" not in info and info.get("resolved"):
                    findings.append(Finding(
                        id=str(uuid.uuid4()),
                        type=FindingType.DEPENDENCY_VULN,
                        severity=Severity.MEDIUM,
                        title=f"Missing integrity hash: {path}",
                        description="Package lacks integrity verification",
                        file_path=str(lock_file),
                        cwe_id="CWE-494",
                        fix_suggestion="Regenerate lock file with npm install",
                        metadata={"package": path}
                    ))
    
    except Exception:
        # Lock file parsing errors are not critical
        pass
    
    return findings


def _scan_python_deps(req_file: Path) -> List[Finding]:
    """Scan requirements.txt for issues."""
    findings = []
    
    try:
        content = req_file.read_text()
        lines = content.splitlines()
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # Parse package name and version
            if "==" in line:
                package, version = line.split("==", 1)
            elif ">=" in line or "<=" in line:
                package = line.split("[<>=]")[0]
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    type=FindingType.DEPENDENCY_VULN,
                    severity=Severity.LOW,
                    title=f"Flexible version constraint: {package}",
                    description=f"Using flexible version constraints can lead to unexpected updates",
                    file_path=str(req_file),
                    line_number=i,
                    cwe_id="CWE-1104",
                    fix_suggestion="Pin to specific versions for reproducible builds",
                    metadata={"line": line}
                ))
            else:
                package = line.split("[")[0]  # Handle extras like pkg[extra]
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    type=FindingType.DEPENDENCY_VULN,
                    severity=Severity.MEDIUM,
                    title=f"Unpinned dependency: {package}",
                    description=f"No version specified for '{package}'",
                    file_path=str(req_file),
                    line_number=i,
                    cwe_id="CWE-1104",
                    fix_suggestion="Specify exact version with ==",
                    metadata={"package": package}
                ))
            
            # Check for typosquatting
            package = package.strip()
            typo_findings = _check_typosquatting(package, str(req_file), i)
            findings.extend(typo_findings)
    
    except Exception as e:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            type=FindingType.SCHEMA_VIOLATION,
            severity=Severity.LOW,
            title="Failed to parse requirements.txt",
            description=str(e),
            file_path=str(req_file),
            cwe_id="CWE-20"
        ))
    
    return findings


def _scan_pipfile_lock(lock_file: Path) -> List[Finding]:
    """Scan Pipfile.lock for issues."""
    findings = []
    
    try:
        data = json.loads(lock_file.read_text())
        
        for section in ["default", "develop"]:
            if section in data:
                for package, info in data[section].items():
                    # Check for packages without hashes
                    if not info.get("hashes"):
                        findings.append(Finding(
                            id=str(uuid.uuid4()),
                            type=FindingType.DEPENDENCY_VULN,
                            severity=Severity.MEDIUM,
                            title=f"Missing hash verification: {package}",
                            description="Package lacks hash verification",
                            file_path=str(lock_file),
                            cwe_id="CWE-494",
                            fix_suggestion="Regenerate lock file with pipenv lock",
                            metadata={"package": package}
                        ))
    
    except Exception:
        pass
    
    return findings


def _scan_go_deps(go_mod: Path) -> List[Finding]:
    """Scan go.mod for issues."""
    findings = []
    
    try:
        content = go_mod.read_text()
        lines = content.splitlines()
        
        for i, line in enumerate(lines, 1):
            if line.strip().startswith("require"):
                continue
            
            # Look for replace directives (can be supply chain risk)
            if line.strip().startswith("replace"):
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    type=FindingType.DEPENDENCY_VULN,
                    severity=Severity.MEDIUM,
                    title="Go module replacement detected",
                    description=f"Replace directive can introduce supply chain risks",
                    file_path=str(go_mod),
                    line_number=i,
                    cwe_id="CWE-494",
                    fix_suggestion="Review if replacement is necessary",
                    metadata={"line": line.strip()}
                ))
    
    except Exception:
        pass
    
    return findings


def _scan_cargo_deps(cargo_toml: Path) -> List[Finding]:
    """Scan Cargo.toml for issues."""
    findings = []
    
    try:
        import toml
        data = toml.loads(cargo_toml.read_text())
        
        deps = data.get("dependencies", {})
        for package, spec in deps.items():
            if isinstance(spec, dict) and spec.get("git"):
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    type=FindingType.DEPENDENCY_VULN,
                    severity=Severity.MEDIUM,
                    title=f"Git dependency: {package}",
                    description="Using git dependencies can be a supply chain risk",
                    file_path=str(cargo_toml),
                    cwe_id="CWE-494",
                    fix_suggestion="Use crates.io published versions",
                    metadata={"package": package, "git": spec["git"]}
                ))
    
    except Exception:
        pass
    
    return findings


def _check_typosquatting(package: str, file_path: str, line_num: int = None) -> List[Finding]:
    """Check if package name might be typosquatted."""
    findings = []
    
    # Check Levenshtein distance to popular packages
    import Levenshtein
    
    for popular in POPULAR_PACKAGES:
        distance = Levenshtein.distance(package.lower(), popular.lower())
        if 0 < distance <= 2:
            finding = Finding(
                id=str(uuid.uuid4()),
                type=FindingType.TYPOSQUATTING,
                severity=Severity.HIGH,
                title=f"Possible typosquatting: {package}",
                description=f"Package '{package}' is very similar to popular package '{popular}'",
                file_path=file_path,
                line_number=line_num,
                cwe_id="CWE-601",
                fix_suggestion=f"Did you mean '{popular}'?",
                metadata={"similar_to": popular, "distance": distance}
            )
            findings.append(finding)
    
    return findings


def _check_cves(package: str, version: str, file_path: str) -> List[Finding]:
    """Check for known CVEs in package."""
    findings = []
    
    # Check our mock CVE database
    pkg_key = f"{package}@{version}"
    if pkg_key in KNOWN_CVES:
        for cve in KNOWN_CVES[pkg_key]:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                type=FindingType.DEPENDENCY_VULN,
                severity=Severity[cve["severity"].upper()],
                title=f"Known vulnerability: {cve['cve']}",
                description=cve["description"],
                file_path=file_path,
                cwe_id="CWE-937",
                fix_suggestion=f"Update {package} to a patched version",
                metadata={"package": package, "version": version, "cve": cve["cve"]}
            ))
    
    return findings


def _calculate_risk_score(findings: List[Finding]) -> float:
    """Calculate total risk score from findings."""
    severity_scores = {
        Severity.CRITICAL: 10.0,
        Severity.HIGH: 7.0,
        Severity.MEDIUM: 4.0,
        Severity.LOW: 1.0,
        Severity.INFO: 0.0
    }
    
    total = 0.0
    for finding in findings:
        total += severity_scores.get(finding.severity, 0.0)
    
    return min(total, 10.0)