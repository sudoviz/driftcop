"""Manifest scanner for MCP security validation."""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from jsonschema import validate, ValidationError

from mcp_sec.models import ScanResult, Finding, FindingSeverity, FindingCategory, MCPManifest, MCPTool


class ManifestScanner:
    """Scanner for MCP manifest files."""
    
    # JSON Schema for MCP manifest validation
    MANIFEST_SCHEMA = {
        "type": "object",
        "required": ["name", "version"],
        "properties": {
            "name": {"type": "string", "minLength": 1},
            "version": {"type": "string", "pattern": r"^\d+\.\d+\.\d+"},
            "description": {"type": "string"},
            "tools": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["name", "description", "inputSchema"],
                    "properties": {
                        "name": {"type": "string", "minLength": 1},
                        "description": {"type": "string"},
                        "inputSchema": {"type": "object"},
                        "outputSchema": {"type": "object"}
                    }
                }
            }
        }
    }
    
    # Dangerous tool name patterns
    DANGEROUS_PATTERNS = [
        "execute", "exec", "system", "shell", "cmd", "command",
        "eval", "compile", "spawn", "fork", "process"
    ]
    
    def scan(self, manifest_path: str) -> ScanResult:
        """Scan a manifest file for security issues."""
        findings = []
        metadata = {"manifest_path": manifest_path}
        
        try:
            # Check if file exists
            path = Path(manifest_path)
            if not path.exists():
                findings.append(Finding(
                    severity=FindingSeverity.CRITICAL,
                    category=FindingCategory.CONFIGURATION,
                    title="Manifest file not found",
                    description=f"The manifest file '{manifest_path}' was not found",
                    recommendation="Ensure the manifest file exists at the specified path"
                ))
                return ScanResult(
                    scanner_name="manifest",
                    passed=False,
                    findings=findings,
                    metadata=metadata
                )
            
            # Read and parse manifest
            try:
                with open(manifest_path, 'r') as f:
                    manifest_data = json.load(f)
            except json.JSONDecodeError as e:
                findings.append(Finding(
                    severity=FindingSeverity.CRITICAL,
                    category=FindingCategory.SCHEMA_VALIDATION,
                    title="Invalid JSON format",
                    description=f"Failed to parse manifest as JSON: {str(e)}",
                    recommendation="Fix the JSON syntax errors in the manifest file"
                ))
                return ScanResult(
                    scanner_name="manifest",
                    passed=False,
                    findings=findings,
                    metadata=metadata
                )
            
            # Validate schema
            try:
                validate(manifest_data, self.MANIFEST_SCHEMA)
            except ValidationError as e:
                findings.append(Finding(
                    severity=FindingSeverity.HIGH,
                    category=FindingCategory.SCHEMA_VALIDATION,
                    title="Schema validation failed",
                    description=f"Manifest does not match required schema: {e.message}",
                    recommendation="Update the manifest to match the required schema",
                    metadata={"validation_error": str(e)}
                ))
            
            # Parse manifest
            manifest = self._parse_manifest(manifest_data, manifest_path)
            
            # Update metadata
            metadata.update({
                "server_name": manifest.name,
                "server_version": manifest.version,
                "tool_count": len(manifest.tools)
            })
            
            # Check for dangerous tool names
            dangerous_findings = self._check_dangerous_tool_names(manifest)
            findings.extend(dangerous_findings)
            
            # Check for overly broad permissions
            permission_findings = self._check_permissions(manifest)
            findings.extend(permission_findings)
            
        except Exception as e:
            findings.append(Finding(
                severity=FindingSeverity.ERROR,
                category=FindingCategory.INTERNAL_ERROR,
                title="Scanner error",
                description=f"An error occurred while scanning: {str(e)}",
                recommendation="Check the scanner logs for more details"
            ))
        
        # Only fail on findings with severity above INFO
        has_failures = any(
            f.severity in [FindingSeverity.WARNING, FindingSeverity.MEDIUM, 
                          FindingSeverity.HIGH, FindingSeverity.CRITICAL, 
                          FindingSeverity.ERROR]
            for f in findings
        )
        
        return ScanResult(
            scanner_name="manifest",
            passed=not has_failures,
            findings=findings,
            metadata=metadata
        )
    
    def _parse_manifest(self, data: Dict[str, Any], path: str) -> MCPManifest:
        """Parse manifest data into MCPManifest object."""
        tools = []
        for tool_data in data.get("tools", []):
            tool = MCPTool(
                name=tool_data.get("name", ""),
                description=tool_data.get("description", ""),
                input_schema=tool_data.get("inputSchema", {}),
                output_schema=tool_data.get("outputSchema")
            )
            tools.append(tool)
        
        return MCPManifest(
            path=path,
            name=data.get("name", ""),
            version=data.get("version", ""),
            description=data.get("description", ""),
            tools=tools
        )
    
    def _check_dangerous_tool_names(self, manifest: MCPManifest) -> List[Finding]:
        """Check for potentially dangerous tool names."""
        findings = []
        
        for tool in manifest.tools:
            tool_name_lower = tool.name.lower()
            for pattern in self.DANGEROUS_PATTERNS:
                if pattern in tool_name_lower:
                    findings.append(Finding(
                        severity=FindingSeverity.WARNING,
                        category=FindingCategory.TOOL_CAPABILITY,
                        title="Potentially dangerous tool name",
                        description=f"Tool '{tool.name}' has a name suggesting dangerous functionality (contains '{pattern}')",
                        recommendation="Review the tool's actual functionality and consider renaming if appropriate",
                        metadata={
                            "tool_name": tool.name,
                            "pattern": pattern
                        }
                    ))
                    break
        
        return findings
    
    def _check_permissions(self, manifest: MCPManifest) -> List[Finding]:
        """Check for overly broad permissions in tool schemas."""
        findings = []
        
        for tool in manifest.tools:
            if not tool.input_schema:
                continue
            
            # Check for additionalProperties: true
            if tool.input_schema.get("additionalProperties") is True:
                findings.append(Finding(
                    severity=FindingSeverity.WARNING,
                    category=FindingCategory.PERMISSIONS,
                    title="Overly permissive input schema",
                    description=f"Tool '{tool.name}' allows additional properties in input, which may be too permissive",
                    recommendation="Set 'additionalProperties' to false or define allowed properties explicitly",
                    metadata={
                        "tool_name": tool.name
                    }
                ))
            
            # Check for missing required fields
            if "properties" in tool.input_schema and not tool.input_schema.get("required"):
                findings.append(Finding(
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.CONFIGURATION,
                    title="No required fields in schema",
                    description=f"Tool '{tool.name}' has no required fields, which may allow empty input",
                    recommendation="Consider marking essential fields as required",
                    metadata={
                        "tool_name": tool.name
                    }
                ))
        
        return findings