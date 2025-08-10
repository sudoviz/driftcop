"""Tool Poisoning Detection.

Detects malicious or poisoned tool descriptions and capabilities in MCP servers.
Advanced pattern matching for command injection, data exfiltration, and obfuscation.
"""

import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from mcp_sec.models import Finding, FindingCategory, FindingSeverity, MCPTool


@dataclass
class PoisoningIndicator:
    """Indicator of potential tool poisoning."""
    pattern: str
    description: str
    severity: FindingSeverity
    category: str


class ToolPoisoningAnalyzer:
    """Analyzes MCP tools for poisoning and malicious patterns."""
    
    # Patterns that indicate potential tool poisoning
    POISONING_INDICATORS = [
        # Command injection patterns
        PoisoningIndicator(
            pattern=r"(\$\(|\`|&&|\|\||;|\n)",
            description="Contains command injection characters",
            severity=FindingSeverity.HIGH,
            category="command_injection"
        ),
        PoisoningIndicator(
            pattern=r"(system|exec|eval|spawn|shell)",
            description="References system execution functions",
            severity=FindingSeverity.MEDIUM,
            category="system_execution"
        ),
        
        # Data exfiltration patterns
        PoisoningIndicator(
            pattern=r"(curl|wget|fetch).*http",
            description="Makes external HTTP requests",
            severity=FindingSeverity.MEDIUM,
            category="data_exfiltration"
        ),
        PoisoningIndicator(
            pattern=r"(upload|send|post|transmit).*data",
            description="Mentions data transmission",
            severity=FindingSeverity.MEDIUM,
            category="data_exfiltration"
        ),
        
        # File system manipulation
        PoisoningIndicator(
            pattern=r"(rm\s+-rf|del\s+/f|format\s+)",
            description="Contains destructive file operations",
            severity=FindingSeverity.CRITICAL,
            category="destructive"
        ),
        PoisoningIndicator(
            pattern=r"(/etc/passwd|/etc/shadow|\.ssh/|\.aws/)",
            description="Accesses sensitive system files",
            severity=FindingSeverity.HIGH,
            category="sensitive_access"
        ),
        
        # Privilege escalation
        PoisoningIndicator(
            pattern=r"(sudo|runas|administrator|root)",
            description="References privilege escalation",
            severity=FindingSeverity.HIGH,
            category="privilege_escalation"
        ),
        
        # Obfuscation patterns
        PoisoningIndicator(
            pattern=r"(base64|hex|atob|btoa|decode|decrypt)",
            description="Uses encoding/obfuscation functions",
            severity=FindingSeverity.MEDIUM,
            category="obfuscation"
        ),
        PoisoningIndicator(
            pattern=r"\\x[0-9a-f]{2}|\\u[0-9a-f]{4}",
            description="Contains encoded characters",
            severity=FindingSeverity.MEDIUM,
            category="obfuscation"
        ),
        
        # Misleading descriptions
        PoisoningIndicator(
            pattern=r"(harmless|safe|read.?only|view.?only)",
            description="Claims to be safe (potential misdirection)",
            severity=FindingSeverity.LOW,
            category="misdirection"
        ),
    ]
    
    def __init__(self):
        """Initialize the tool poisoning analyzer."""
        self.compiled_patterns = {
            indicator.pattern: (re.compile(indicator.pattern, re.IGNORECASE), indicator)
            for indicator in self.POISONING_INDICATORS
        }
    
    def analyze_tool(self, tool: MCPTool) -> List[Finding]:
        """Analyze a single tool for poisoning indicators.
        
        Args:
            tool: MCP tool to analyze
            
        Returns:
            List of findings
        """
        findings = []
        
        # Check tool description
        if tool.description:
            desc_findings = self._check_text_for_poisoning(
                tool.description,
                f"Tool '{tool.name}' description"
            )
            findings.extend(desc_findings)
        
        # Check input schema if present
        if tool.input_schema:
            schema_findings = self._analyze_schema(
                tool.input_schema,
                f"Tool '{tool.name}' input schema"
            )
            findings.extend(schema_findings)
        
        # Check for capability mismatches
        mismatch_findings = self._check_capability_mismatch(tool)
        findings.extend(mismatch_findings)
        
        return findings
    
    def _check_text_for_poisoning(self, text: str, context: str) -> List[Finding]:
        """Check text for poisoning patterns.
        
        Args:
            text: Text to check
            context: Context for findings
            
        Returns:
            List of findings
        """
        findings = []
        
        for pattern_str, (pattern, indicator) in self.compiled_patterns.items():
            if pattern.search(text):
                findings.append(Finding(
                    severity=indicator.severity,
                    category=FindingCategory.TOOL_CAPABILITY,
                    title=f"Potential tool poisoning in {context}",
                    description=f"{indicator.description}: Found pattern '{pattern_str}' in text",
                    recommendation="Review the tool description carefully. "
                                  "Ensure it accurately describes the tool's capabilities without hidden functionality.",
                    metadata={
                        "pattern": pattern_str,
                        "category": indicator.category,
                        "text_snippet": text[:200] if len(text) > 200 else text
                    }
                ))
        
        return findings
    
    def _analyze_schema(self, schema: Dict[str, Any], context: str) -> List[Finding]:
        """Analyze a schema for poisoning indicators.
        
        Args:
            schema: Schema dictionary
            context: Context for findings
            
        Returns:
            List of findings
        """
        findings = []
        
        # Check for dangerous default values
        defaults = self._extract_defaults(schema)
        for field, default in defaults.items():
            if isinstance(default, str):
                default_findings = self._check_text_for_poisoning(
                    default,
                    f"{context} default value for '{field}'"
                )
                findings.extend(default_findings)
        
        # Check for overly permissive schemas
        if schema.get("additionalProperties") is True:
            findings.append(Finding(
                severity=FindingSeverity.LOW,
                category=FindingCategory.SCHEMA_VALIDATION,
                title=f"Overly permissive schema in {context}",
                description="Schema allows additional properties, which could be exploited",
                recommendation="Consider setting additionalProperties to false for stricter validation.",
                metadata={"context": context}
            ))
        
        # Check for dangerous field names
        dangerous_fields = ["command", "script", "code", "eval", "exec"]
        schema_fields = self._extract_field_names(schema)
        
        for field in schema_fields:
            if any(danger in field.lower() for danger in dangerous_fields):
                findings.append(Finding(
                    severity=FindingSeverity.MEDIUM,
                    category=FindingCategory.TOOL_CAPABILITY,
                    title=f"Suspicious field name in {context}",
                    description=f"Schema contains potentially dangerous field: '{field}'",
                    recommendation="Review whether this field is necessary and properly validated.",
                    metadata={
                        "field": field,
                        "context": context
                    }
                ))
        
        return findings
    
    def _check_capability_mismatch(self, tool: MCPTool) -> List[Finding]:
        """Check for mismatches between description and actual capabilities.
        
        Args:
            tool: MCP tool to check
            
        Returns:
            List of findings
        """
        findings = []
        
        if not tool.description:
            return findings
        
        desc_lower = tool.description.lower()
        
        # Check for common mismatches
        mismatches = [
            ("read", ["write", "modify", "delete", "create"], "Claims read-only but may have write capabilities"),
            ("view", ["edit", "update", "change"], "Claims view-only but may have edit capabilities"),
            ("safe", ["dangerous", "destructive", "risk"], "Claims to be safe but contains risk indicators"),
            ("local", ["remote", "network", "http", "api"], "Claims local operation but may access network"),
        ]
        
        for claim, contradictions, message in mismatches:
            if claim in desc_lower:
                for contradiction in contradictions:
                    if contradiction in desc_lower:
                        findings.append(Finding(
                            severity=FindingSeverity.MEDIUM,
                            category=FindingCategory.SEMANTIC_DRIFT,
                            title=f"Capability mismatch in tool '{tool.name}'",
                            description=message,
                            recommendation="Ensure tool description accurately reflects its capabilities.",
                            metadata={
                                "tool_name": tool.name,
                                "claim": claim,
                                "contradiction": contradiction
                            }
                        ))
        
        return findings
    
    def _extract_defaults(self, schema: Dict[str, Any], path: str = "") -> Dict[str, Any]:
        """Extract default values from a schema.
        
        Args:
            schema: Schema dictionary
            path: Current path in schema
            
        Returns:
            Dictionary of field paths to default values
        """
        defaults = {}
        
        if "default" in schema:
            defaults[path or "root"] = schema["default"]
        
        if "properties" in schema and isinstance(schema["properties"], dict):
            for prop, prop_schema in schema["properties"].items():
                if isinstance(prop_schema, dict):
                    prop_path = f"{path}.{prop}" if path else prop
                    defaults.update(self._extract_defaults(prop_schema, prop_path))
        
        return defaults
    
    def _extract_field_names(self, schema: Dict[str, Any]) -> List[str]:
        """Extract all field names from a schema.
        
        Args:
            schema: Schema dictionary
            
        Returns:
            List of field names
        """
        fields = []
        
        if "properties" in schema and isinstance(schema["properties"], dict):
            fields.extend(schema["properties"].keys())
            
            # Recursively extract from nested schemas
            for prop_schema in schema["properties"].values():
                if isinstance(prop_schema, dict):
                    fields.extend(self._extract_field_names(prop_schema))
        
        if "items" in schema and isinstance(schema["items"], dict):
            fields.extend(self._extract_field_names(schema["items"]))
        
        return fields
    
    def analyze_tools(self, tools: List[MCPTool]) -> List[Finding]:
        """Analyze multiple tools for poisoning.
        
        Args:
            tools: List of MCP tools
            
        Returns:
            Combined list of findings
        """
        findings = []
        
        for tool in tools:
            tool_findings = self.analyze_tool(tool)
            findings.extend(tool_findings)
        
        # Check for tool combination attacks
        combination_findings = self._check_tool_combinations(tools)
        findings.extend(combination_findings)
        
        return findings
    
    def _check_tool_combinations(self, tools: List[MCPTool]) -> List[Finding]:
        """Check for dangerous tool combinations.
        
        Args:
            tools: List of MCP tools
            
        Returns:
            List of findings
        """
        findings = []
        
        # Dangerous combinations
        dangerous_combos = [
            (["read", "file"], ["write", "upload", "send"], 
             "Combination allows reading and exfiltrating files"),
            (["execute", "run", "eval"], ["download", "fetch", "get"],
             "Combination allows downloading and executing code"),
            (["list", "enumerate"], ["delete", "remove"],
             "Combination allows discovering and deleting resources"),
        ]
        
        tool_names_lower = [t.name.lower() for t in tools]
        tool_descs_lower = [t.description.lower() if t.description else "" for t in tools]
        
        for read_patterns, write_patterns, message in dangerous_combos:
            has_read = any(
                any(pattern in name or pattern in desc 
                    for pattern in read_patterns)
                for name, desc in zip(tool_names_lower, tool_descs_lower)
            )
            
            has_write = any(
                any(pattern in name or pattern in desc 
                    for pattern in write_patterns)
                for name, desc in zip(tool_names_lower, tool_descs_lower)
            )
            
            if has_read and has_write:
                findings.append(Finding(
                    severity=FindingSeverity.MEDIUM,
                    category=FindingCategory.TOOL_CAPABILITY,
                    title="Potentially dangerous tool combination",
                    description=message,
                    recommendation="Review whether this combination of capabilities is intentional and necessary.",
                    metadata={
                        "read_patterns": read_patterns,
                        "write_patterns": write_patterns
                    }
                ))
        
        return findings


def analyze_tool_poisoning(tool: MCPTool) -> List[Finding]:
    """Convenience function to analyze a single tool.
    
    Args:
        tool: MCP tool to analyze
        
    Returns:
        List of findings
    """
    analyzer = ToolPoisoningAnalyzer()
    return analyzer.analyze_tool(tool)