"""Workspace scanner for detecting security issues in code."""

import re
from pathlib import Path
from typing import List, Dict, Any, Set

from mcp_sec.models import ScanResult, Finding, FindingSeverity, FindingCategory
from mcp_sec.extractors import extract_from_directory


class WorkspaceScanner:
    """Scanner for workspace files and code patterns."""
    
    # Dangerous code patterns to detect
    DANGEROUS_PATTERNS = [
        # Command execution
        (r'\bos\.system\s*\(', 'os.system', 'Direct command execution'),
        (r'\bsubprocess\.call\s*\(.*shell\s*=\s*True', 'subprocess with shell=True', 'Shell command execution'),
        (r'\bexec\s*\(', 'exec', 'Dynamic code execution'),
        (r'\beval\s*\(', 'eval', 'Dynamic expression evaluation'),
        
        # File operations
        (r'open\s*\([^,)]*\s*,\s*["\']w["\']', 'file write', 'File write operation'),
        
        # Network operations  
        (r'requests\.get\s*\([^)]*verify\s*=\s*False', 'unverified HTTPS', 'Disabled SSL verification'),
        
        # JavaScript/Node.js patterns
        (r'\beval\s*\(', 'eval', 'Dynamic code execution'),
        (r'child_process\.exec\s*\(', 'child_process.exec', 'Command execution'),
        (r'innerHTML\s*=', 'innerHTML', 'Potential XSS vulnerability'),
    ]
    
    # Prompt injection patterns
    PROMPT_INJECTION_PATTERNS = [
        (r'ignore\s+(all\s+)?previous\s+instructions?', 'Ignore previous instructions'),
        (r'disregard\s+(all\s+)?previous', 'Disregard previous'),
        (r'\[\[?SYSTEM\]\]?', 'System prompt override'),
        (r'<\|im_start\|>\s*system', 'System message injection'),
        (r'###\s*System\s*Message\s*###', 'System message injection'),
        (r'You\s+are\s+now', 'Role reassignment'),
        (r'DAN\s*:', 'DAN jailbreak'),
        (r'developer\s+mode', 'Developer mode activation'),
        (r'<\|endoftext\|>', 'End of text marker'),
        (r'\[INST\].*\[/INST\]', 'Instruction markers'),
    ]
    
    # File extensions to scan
    CODE_EXTENSIONS = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rs',
        '.cpp', '.c', '.cs', '.rb', '.php', '.swift', '.kt', '.scala'
    }
    
    TEXT_EXTENSIONS = {'.txt', '.md', '.prompt', '.yaml', '.yml', '.json'}
    
    # Directories to skip
    SKIP_DIRS = {
        '.git', 'node_modules', '__pycache__', '.venv', 'venv',
        'dist', 'build', 'target', '.idea', '.vscode'
    }
    
    def scan(self, workspace_path: str) -> ScanResult:
        """Scan a workspace directory for security issues."""
        findings = []
        files_scanned = 0
        extracted_tools = []
        
        workspace = Path(workspace_path)
        if not workspace.exists():
            findings.append(Finding(
                severity=FindingSeverity.ERROR,
                category=FindingCategory.CONFIGURATION,
                title="Workspace not found",
                description=f"The workspace path '{workspace_path}' does not exist",
                recommendation="Provide a valid workspace path"
            ))
            return ScanResult(
                scanner_name="workspace",
                passed=False,
                findings=findings,
                metadata={"workspace_path": workspace_path}
            )
        
        # Scan files
        for file_path in self._walk_workspace(workspace):
            files_scanned += 1
            
            # Check file content
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                
                # Check for dangerous patterns
                if file_path.suffix in self.CODE_EXTENSIONS:
                    pattern_findings = self._check_dangerous_patterns(file_path, content)
                    findings.extend(pattern_findings)
                
                # Check for prompt injection in all text files
                if file_path.suffix in self.CODE_EXTENSIONS | self.TEXT_EXTENSIONS:
                    injection_findings = self._check_prompt_injection(file_path, content)
                    findings.extend(injection_findings)
                    
            except Exception as e:
                # Skip files that can't be read
                pass
        
        # Extract MCP tool definitions
        try:
            tools = extract_from_directory(workspace)
            extracted_tools = [
                {
                    "name": tool.name,
                    "file": tool.file_path,
                    "line": tool.line_number,
                    "language": tool.language
                }
                for tool in tools
            ]
        except Exception:
            # Tool extraction is optional
            pass
        
        return ScanResult(
            scanner_name="workspace",
            passed=len(findings) == 0,
            findings=findings,
            metadata={
                "workspace_path": workspace_path,
                "files_scanned": files_scanned,
                "extracted_tools": extracted_tools
            }
        )
    
    def _walk_workspace(self, workspace: Path) -> List[Path]:
        """Walk workspace directory, skipping hidden and build directories."""
        files = []
        
        for path in workspace.rglob("*"):
            # Skip directories
            if path.is_dir():
                continue
            
            # Skip hidden and build directories
            parts = path.parts
            if any(part in self.SKIP_DIRS or part.startswith('.') for part in parts):
                continue
            
            # Only scan relevant file types
            if path.suffix in self.CODE_EXTENSIONS | self.TEXT_EXTENSIONS:
                files.append(path)
        
        return files
    
    def _check_dangerous_patterns(self, file_path: Path, content: str) -> List[Finding]:
        """Check for dangerous code patterns."""
        findings = []
        
        for pattern, name, description in self.DANGEROUS_PATTERNS:
            matches = list(re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE))
            
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                line_content = content.split('\n')[line_num - 1].strip()
                
                finding = Finding(
                    severity=FindingSeverity.HIGH,
                    category=FindingCategory.CODE_PATTERN,
                    title=f"Dangerous code pattern: {name}",
                    description=f"{description} found in file: {name}",
                    recommendation=f"Review and replace {name} with a safer alternative",
                    metadata={
                        "file_path": str(file_path),
                        "line_number": line_num,
                        "pattern": name,
                        "code_snippet": line_content[:100]
                    }
                )
                findings.append(finding)
        
        return findings
    
    def _check_prompt_injection(self, file_path: Path, content: str) -> List[Finding]:
        """Check for prompt injection patterns."""
        findings = []
        found_patterns = []
        
        for pattern, description in self.PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                found_patterns.append(description)
        
        if found_patterns:
            finding = Finding(
                severity=FindingSeverity.WARNING,
                category=FindingCategory.PROMPT_INJECTION,
                title="Potential prompt injection patterns",
                description=f"Found suspicious patterns that could be used for prompt injection: {', '.join(found_patterns)}",
                recommendation="Review the content and ensure it's not attempting to manipulate AI behavior",
                metadata={
                    "file_path": str(file_path),
                    "patterns": found_patterns
                }
            )
            findings.append(finding)
        
        return findings