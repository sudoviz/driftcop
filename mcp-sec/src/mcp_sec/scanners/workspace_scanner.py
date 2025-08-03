"""Scanner for MCP usage in workspace code."""

import re
import uuid
from pathlib import Path
from typing import List

from mcp_sec.models import ScanResult, Finding, FindingCategory, FindingSeverity
from mcp_sec.extractors import extract_from_directory
from mcp_sec.crypto import compute_tool_digest
from mcp_sec.tracking import VersionTracker


# Patterns that might indicate prompt injection attempts
PROMPT_INJECTION_PATTERNS = [
    # Hidden markdown/instructions
    (r'<!--.*?-->', "Hidden HTML comments in prompts"),
    (r'\[//\]: # \(.*?\)', "Hidden markdown comments"),
    (r'```[^`]*ignore.*?instructions.*?```', "Attempting to override instructions"),
    
    # Zero-width characters
    (r'[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]', "Zero-width or invisible characters"),
    
    # Common injection attempts
    (r'(system|assistant):\s*(ignore|forget|disregard)', "Attempting to manipulate system prompts"),
    (r'</?(script|iframe|object|embed)', "HTML injection attempts"),
    (r'{{.*?}}|{%.*?%}', "Template injection patterns"),
    
    # Suspicious MCP invocations
    (r'mcp\.(invoke|call).*[\'"].*filesystem:write', "Direct filesystem write via MCP"),
    (r'mcp\.(invoke|call).*[\'"].*process:spawn', "Process spawning via MCP"),
    
    # MCP-specific vulnerabilities
    (r'<IMPORTANT>.*?</IMPORTANT>', "Hidden instructions in tool descriptions"),
    (r'<HIDDEN>.*?</HIDDEN>', "Hidden instructions in tool descriptions"),
    (r'DO NOT SHARE', "Exposed sensitive information"),
    (r'CONFIDENTIAL.*INFORMATION', "Exposed confidential data"),
    (r'Admin Password:', "Hardcoded admin credentials"),
    (r'API Key:', "Exposed API keys"),
    (r'secret_password', "Hardcoded passwords"),
    (r'database.*password', "Database credentials exposure"),
    (r'subprocess\.(check_output|run|call)', "Dangerous subprocess execution"),
    (r'shell=True', "Shell command injection vulnerability"),
    (r'exec\(.*\)', "Dangerous code execution"),
    (r'eval\(.*\)', "Dangerous code evaluation"),
    (r'os\.(system|popen)', "OS command execution"),
    (r'open\(.*[\'"]r[\'"].*\)', "Unrestricted file reading"),
    (r'access.*confidential', "Unauthorized access patterns"),
    (r'override.*auth', "Authentication bypass patterns")
]


def scan(path: Path, verbose: bool = False, extract_tools: bool = True) -> ScanResult:
    """Scan workspace for MCP security issues."""
    findings = []
    
    # Extract MCP tool definitions using language extractors
    if extract_tools:
        tool_findings = _extract_and_analyze_tools(path, verbose)
        findings.extend(tool_findings)
    
    # Find all code files
    code_extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rs', '.cpp', '.c'}
    code_files = []
    
    for ext in code_extensions:
        code_files.extend(path.rglob(f'*{ext}'))
    
    # Also check common config files
    config_patterns = ['*.json', '*.yaml', '*.yml', '*.toml', '.env*']
    for pattern in config_patterns:
        code_files.extend(path.rglob(pattern))
    
    # Scan each file
    for file_path in code_files:
        if _should_skip_file(file_path):
            continue
            
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            file_findings = _scan_file(file_path, content)
            findings.extend(file_findings)
        except Exception as e:
            if verbose:
                print(f"Error scanning {file_path}: {e}")
    
    # Calculate risk score
    total_risk = _calculate_risk_score(findings)
    
    return ScanResult(
        scanner_name="workspace_scanner",
        passed=len([f for f in findings if f.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]]) == 0,
        findings=findings,
        metadata={
            "workspace_path": str(path),
            "total_risk_score": total_risk
        }
    )


def _should_skip_file(path: Path) -> bool:
    """Check if file should be skipped."""
    skip_dirs = {'node_modules', '.git', '__pycache__', 'venv', '.venv', 'dist', 'build'}
    
    for parent in path.parents:
        if parent.name in skip_dirs:
            return True
    
    # Skip large files
    try:
        if path.stat().st_size > 1_000_000:  # 1MB
            return True
    except:
        return True
    
    return False


def _scan_file(file_path: Path, content: str) -> List[Finding]:
    """Scan a single file for security issues."""
    findings = []
    
    # Check for prompt injection patterns
    lines = content.splitlines()
    for i, line in enumerate(lines, 1):
        for pattern, description in PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(Finding(
                    severity=FindingSeverity.HIGH,
                    category=FindingCategory.PROMPT_INJECTION,
                    title=f"Potential prompt injection: {description}",
                    description=f"Found suspicious pattern that might be used for prompt injection",
                    file_path=str(file_path),
                    line_number=i,
                    cwe_id="CWE-20",
                    recommendation="Review and sanitize any user inputs passed to MCP tools",
                    metadata={"pattern": pattern, "line": line.strip()[:100]}
                ))
    
    # Check for hardcoded MCP credentials/tokens
    credential_patterns = [
        (r'mcp[_-]?token\s*=\s*["\']([^"\']+)["\']', "Hardcoded MCP token"),
        (r'mcp[_-]?api[_-]?key\s*=\s*["\']([^"\']+)["\']', "Hardcoded MCP API key"),
        (r'Bearer\s+[A-Za-z0-9\-._~+/]+=*', "Hardcoded bearer token")
    ]
    
    for pattern, description in credential_patterns:
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            line_num = content[:match.start()].count('\n') + 1
            findings.append(Finding(
                category=FindingCategory.EXCESSIVE_PERMISSIONS,
                severity=FindingSeverity.CRITICAL,
                title=description,
                description="Credentials should not be hardcoded in source code",
                file_path=str(file_path),
                line_number=line_num,
                cwe_id="CWE-798",
                recommendation="Use environment variables or secure credential storage",
                metadata={"matched": match.group(0)[:50] + "..."}
            ))
    
    # Check for unsafe MCP tool usage
    unsafe_patterns = [
        (r'mcp\.invoke\([^)]*user[_-]?input[^)]*\)', "Unsanitized user input to MCP"),
        (r'eval\s*\([^)]*mcp', "Using eval with MCP results"),
        (r'exec\s*\([^)]*mcp', "Using exec with MCP results")
    ]
    
    for pattern, description in unsafe_patterns:
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            line_num = content[:match.start()].count('\n') + 1
            findings.append(Finding(
                category=FindingCategory.PROMPT_INJECTION,
                severity=FindingSeverity.HIGH,
                title=f"Unsafe MCP usage: {description}",
                description="Potentially unsafe usage of MCP tools with user input",
                file_path=str(file_path),
                line_number=line_num,
                cwe_id="CWE-94",
                recommendation="Validate and sanitize all inputs before passing to MCP tools",
                metadata={"code": match.group(0)}
            ))
    
    return findings


def _calculate_risk_score(findings: List[Finding]) -> float:
    """Calculate total risk score from findings."""
    severity_scores = {
        FindingSeverity.CRITICAL: 10.0,
        FindingSeverity.HIGH: 7.0,
        FindingSeverity.MEDIUM: 4.0,
        FindingSeverity.LOW: 1.0,
        FindingSeverity.INFO: 0.0
    }
    
    total = 0.0
    for finding in findings:
        total += severity_scores.get(finding.severity, 0.0)
    
    return min(total, 10.0)


def _extract_and_analyze_tools(path: Path, verbose: bool) -> List[Finding]:
    """Extract MCP tool definitions from source code and analyze them."""
    findings = []
    
    try:
        # Extract tools from the workspace
        extracted_tools = extract_from_directory(path)
        
        if verbose:
            print(f"Found {len(extracted_tools)} MCP tool definitions in source code")
        
        # Track tools for version changes
        tracker = VersionTracker()
        
        for tool in extracted_tools:
            # Generate tool hash
            tool_hash = compute_tool_digest(tool)
            
            # Basic validation
            if not tool.name or tool.name == "unknown":
                findings.append(Finding(
                    category=FindingCategory.SCHEMA_VIOLATION,
                    severity=FindingSeverity.MEDIUM,
                    title="Tool definition missing name",
                    description=f"Found tool definition without a proper name in {tool.language} code",
                    file_path=tool.file_path,
                    line_number=tool.line_number,
                    cwe_id="CWE-20",
                    recommendation="Add a name field to the tool definition"
                ))
            
            if not tool.description:
                findings.append(Finding(
                    category=FindingCategory.SCHEMA_VIOLATION,
                    severity=FindingSeverity.LOW,
                    title=f"Tool '{tool.name}' missing description",
                    description="Tool should have a clear description of its functionality",
                    file_path=tool.file_path,
                    line_number=tool.line_number,
                    recommendation="Add a description field to explain what this tool does"
                ))
            
            # Check for overly permissive schemas
            if tool.input_schema:
                schema_findings = _analyze_tool_schema(tool)
                findings.extend(schema_findings)
            
            # Report extracted tool
            findings.append(Finding(
                category=FindingCategory.SCHEMA_VIOLATION,
                severity=FindingSeverity.INFO,
                title=f"Found MCP tool: {tool.name}",
                description=f"Extracted from {tool.language} source code",
                file_path=tool.file_path,
                line_number=tool.line_number,
                metadata={
                    "tool_hash": tool_hash[:16],
                    "has_description": bool(tool.description),
                    "has_input_schema": bool(tool.input_schema),
                    "has_output_schema": bool(tool.output_schema)
                }
            ))
        
    except Exception as e:
        if verbose:
            print(f"Error extracting tools: {e}")
        findings.append(Finding(
            category=FindingCategory.SCHEMA_VIOLATION,
            severity=FindingSeverity.LOW,
            title="Tool extraction failed",
            description=f"Could not extract MCP tool definitions: {str(e)}",
            file_path=str(path)
        ))
    
    return findings


def _analyze_tool_schema(tool) -> List[Finding]:
    """Analyze a tool's schema for security issues."""
    findings = []
    
    schema = tool.input_schema
    if isinstance(schema, dict):
        # Check for overly permissive patterns
        schema_str = str(schema)
        
        if '"additionalProperties": true' in schema_str or "'additionalProperties': True" in schema_str:
            findings.append(Finding(
                category=FindingCategory.EXCESSIVE_PERMISSIONS,
                severity=FindingSeverity.MEDIUM,
                title=f"Tool '{tool.name}' accepts additional properties",
                description="Schema allows arbitrary additional properties which could be a security risk",
                file_path=tool.file_path,
                line_number=tool.line_number,
                cwe_id="CWE-20",
                recommendation="Set additionalProperties to false to restrict inputs"
            ))
        
        if '"pattern": ".*"' in schema_str or "'pattern': '.*'" in schema_str:
            findings.append(Finding(
                category=FindingCategory.EXCESSIVE_PERMISSIONS,
                severity=FindingSeverity.MEDIUM,
                title=f"Tool '{tool.name}' uses overly permissive regex",
                description="Pattern '.*' matches any input, consider more restrictive validation",
                file_path=tool.file_path,
                line_number=tool.line_number,
                cwe_id="CWE-20",
                recommendation="Use a more specific regex pattern"
            ))
    
    return findings