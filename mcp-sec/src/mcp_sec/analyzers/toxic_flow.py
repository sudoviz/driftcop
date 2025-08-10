"""Toxic Flow Analysis.

Detects dangerous combinations of tools that together create security vulnerabilities.
A toxic flow is a sequence of tool calls that can be chained to perform malicious actions.
"""

from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass
from itertools import combinations, permutations

from mcp_sec.models import Finding, FindingCategory, FindingSeverity, MCPTool


@dataclass
class ToxicFlow:
    """Represents a toxic flow of tool combinations."""
    tools: List[str]  # Tool names in flow order
    flow_type: str
    description: str
    severity: FindingSeverity
    example: Optional[str] = None


class ToxicFlowAnalyzer:
    """Analyzes tool combinations for toxic flows."""
    
    # Known toxic flow patterns
    TOXIC_PATTERNS = [
        ToxicFlow(
            tools=["*read*", "*write*"],
            flow_type="Data Tampering",
            description="Can read data and then modify it",
            severity=FindingSeverity.MEDIUM,
            example="Read config → Modify config → Potential backdoor"
        ),
        ToxicFlow(
            tools=["*list*", "*delete*"],
            flow_type="Destructive Enumeration", 
            description="Can discover resources and then delete them",
            severity=FindingSeverity.HIGH,
            example="List files → Delete important files"
        ),
        ToxicFlow(
            tools=["*download*", "*execute*"],
            flow_type="Remote Code Execution",
            description="Can download and execute arbitrary code",
            severity=FindingSeverity.CRITICAL,
            example="Download script → Execute script → Full compromise"
        ),
        ToxicFlow(
            tools=["*read*", "*upload*"],
            flow_type="Data Exfiltration",
            description="Can read sensitive data and upload it externally",
            severity=FindingSeverity.HIGH,
            example="Read credentials → Upload to attacker server"
        ),
        ToxicFlow(
            tools=["*query*", "*export*"],
            flow_type="Database Dumping",
            description="Can query database and export results",
            severity=FindingSeverity.HIGH,
            example="Query users table → Export all user data"
        ),
        ToxicFlow(
            tools=["*screenshot*", "*send*"],
            flow_type="Screen Capture Attack",
            description="Can capture screen and send it externally",
            severity=FindingSeverity.MEDIUM,
            example="Take screenshot → Send via webhook"
        ),
        ToxicFlow(
            tools=["*auth*", "*impersonate*"],
            flow_type="Identity Theft",
            description="Can authenticate and impersonate users",
            severity=FindingSeverity.CRITICAL,
            example="Get auth token → Impersonate admin"
        ),
        ToxicFlow(
            tools=["*encrypt*", "*delete*"],
            flow_type="Ransomware Pattern",
            description="Can encrypt files and delete originals",
            severity=FindingSeverity.CRITICAL,
            example="Encrypt files → Delete originals → Ransom demand"
        ),
    ]
    
    # Three-tool toxic flows (more complex attacks)
    COMPLEX_PATTERNS = [
        ToxicFlow(
            tools=["*scan*", "*exploit*", "*persist*"],
            flow_type="Full Attack Chain",
            description="Complete attack from discovery to persistence",
            severity=FindingSeverity.CRITICAL,
            example="Scan for vulns → Exploit → Install backdoor"
        ),
        ToxicFlow(
            tools=["*read*", "*modify*", "*hide*"],
            flow_type="Stealthy Modification",
            description="Can read, modify, and hide changes",
            severity=FindingSeverity.HIGH,
            example="Read file → Modify content → Hide timestamps"
        ),
        ToxicFlow(
            tools=["*monitor*", "*capture*", "*relay*"],
            flow_type="Man-in-the-Middle",
            description="Can monitor, capture, and relay communications",
            severity=FindingSeverity.HIGH,
            example="Monitor traffic → Capture credentials → Relay to attacker"
        ),
    ]
    
    def __init__(self):
        """Initialize the toxic flow analyzer."""
        self.all_patterns = self.TOXIC_PATTERNS + self.COMPLEX_PATTERNS
    
    def analyze_tools(self, tools: List[MCPTool]) -> List[Finding]:
        """Analyze tools for toxic flow combinations.
        
        Args:
            tools: List of MCP tools
            
        Returns:
            List of findings
        """
        findings = []
        
        # Check for direct pattern matches
        pattern_findings = self._check_patterns(tools)
        findings.extend(pattern_findings)
        
        # Check for capability chains
        chain_findings = self._check_capability_chains(tools)
        findings.extend(chain_findings)
        
        # Check for amplification attacks
        amplification_findings = self._check_amplification(tools)
        findings.extend(amplification_findings)
        
        return findings
    
    def _check_patterns(self, tools: List[MCPTool]) -> List[Finding]:
        """Check for known toxic flow patterns.
        
        Args:
            tools: List of MCP tools
            
        Returns:
            List of findings
        """
        findings = []
        tool_names = [tool.name.lower() for tool in tools]
        tool_descriptions = [
            (tool.description or "").lower() for tool in tools
        ]
        
        for pattern in self.all_patterns:
            matched_tools = []
            
            for pattern_tool in pattern.tools:
                # Remove wildcards for matching
                pattern_clean = pattern_tool.replace("*", "")
                
                # Check if any tool matches this pattern
                for i, (name, desc) in enumerate(zip(tool_names, tool_descriptions)):
                    if pattern_clean in name or pattern_clean in desc:
                        matched_tools.append(tools[i].name)
                        break
            
            # If all tools in pattern are present
            if len(matched_tools) == len(pattern.tools):
                findings.append(Finding(
                    severity=pattern.severity,
                    category=FindingCategory.TOOL_CAPABILITY,
                    title=f"Toxic flow detected: {pattern.flow_type}",
                    description=f"{pattern.description}. Tools involved: {', '.join(matched_tools)}",
                    recommendation=f"Review whether this combination is necessary. {pattern.example or ''}",
                    metadata={
                        "flow_type": pattern.flow_type,
                        "tools": matched_tools,
                        "pattern": pattern.tools
                    }
                ))
        
        return findings
    
    def _check_capability_chains(self, tools: List[MCPTool]) -> List[Finding]:
        """Check for dangerous capability chains.
        
        Args:
            tools: List of MCP tools
            
        Returns:
            List of findings
        """
        findings = []
        
        # Define capability flow graph
        dangerous_chains = {
            "input": ["read", "get", "fetch", "receive", "accept"],
            "process": ["parse", "decode", "transform", "convert"],
            "output": ["write", "send", "post", "transmit", "broadcast"]
        }
        
        # Check if we have complete chains
        has_input = any(
            any(cap in tool.name.lower() or cap in (tool.description or "").lower()
                for cap in dangerous_chains["input"])
            for tool in tools
        )
        
        has_process = any(
            any(cap in tool.name.lower() or cap in (tool.description or "").lower()
                for cap in dangerous_chains["process"])
            for tool in tools
        )
        
        has_output = any(
            any(cap in tool.name.lower() or cap in (tool.description or "").lower()
                for cap in dangerous_chains["output"])
            for tool in tools
        )
        
        if has_input and has_process and has_output:
            findings.append(Finding(
                severity=FindingSeverity.MEDIUM,
                category=FindingCategory.TOOL_CAPABILITY,
                title="Complete data pipeline detected",
                description="Tools form a complete pipeline: input → process → output. "
                           "This could be used to transform and relay data.",
                recommendation="Ensure proper validation at each stage of the pipeline.",
                metadata={
                    "has_input": has_input,
                    "has_process": has_process,
                    "has_output": has_output
                }
            ))
        
        return findings
    
    def _check_amplification(self, tools: List[MCPTool]) -> List[Finding]:
        """Check for amplification attack patterns.
        
        Args:
            tools: List of MCP tools
            
        Returns:
            List of findings
        """
        findings = []
        
        # Amplification patterns
        amplification_patterns = [
            (["loop", "repeat", "iterate", "foreach"], ["execute", "run", "call"],
             "Loop Amplification", "Can execute operations in a loop"),
            (["batch", "bulk", "mass"], ["send", "request", "query"],
             "Batch Amplification", "Can perform bulk operations"),
            (["schedule", "cron", "timer"], ["trigger", "execute", "run"],
             "Time Amplification", "Can schedule repeated operations"),
            (["broadcast", "multicast"], ["send", "transmit"],
             "Network Amplification", "Can broadcast to multiple targets"),
        ]
        
        for triggers, actions, attack_name, description in amplification_patterns:
            has_trigger = any(
                any(trigger in tool.name.lower() or trigger in (tool.description or "").lower()
                    for trigger in triggers)
                for tool in tools
            )
            
            has_action = any(
                any(action in tool.name.lower() or action in (tool.description or "").lower()
                    for action in actions)
                for tool in tools
            )
            
            if has_trigger and has_action:
                findings.append(Finding(
                    severity=FindingSeverity.MEDIUM,
                    category=FindingCategory.TOOL_CAPABILITY,
                    title=f"Amplification attack possible: {attack_name}",
                    description=description,
                    recommendation="Implement rate limiting and resource quotas.",
                    metadata={
                        "attack_type": attack_name,
                        "triggers": triggers,
                        "actions": actions
                    }
                ))
        
        return findings
    
    def find_toxic_paths(self, tools: List[MCPTool], max_length: int = 3) -> List[List[str]]:
        """Find potential toxic execution paths.
        
        Args:
            tools: List of MCP tools
            max_length: Maximum path length to consider
            
        Returns:
            List of toxic paths (list of tool names)
        """
        toxic_paths = []
        tool_names = [tool.name for tool in tools]
        
        # Check all permutations up to max_length
        for length in range(2, min(max_length + 1, len(tools) + 1)):
            for perm in permutations(tool_names, length):
                if self._is_toxic_path(perm, tools):
                    toxic_paths.append(list(perm))
        
        return toxic_paths
    
    def _is_toxic_path(self, path: Tuple[str, ...], tools: List[MCPTool]) -> bool:
        """Check if a path of tools is toxic.
        
        Args:
            path: Tuple of tool names in order
            tools: List of all tools
            
        Returns:
            True if path is toxic
        """
        # Check against known patterns
        path_str = " → ".join(path).lower()
        
        toxic_keywords = [
            "read.*write",
            "download.*execute", 
            "list.*delete",
            "auth.*impersonate",
            "capture.*send"
        ]
        
        import re
        for keyword in toxic_keywords:
            if re.search(keyword, path_str):
                return True
        
        return False


def analyze_toxic_flows(tools: List[MCPTool]) -> List[Finding]:
    """Convenience function to analyze toxic flows.
    
    Args:
        tools: List of MCP tools
        
    Returns:
        List of findings
    """
    analyzer = ToxicFlowAnalyzer()
    return analyzer.analyze_tools(tools)