"""Cross-Origin Attack Detection.

Detects cross-origin escalation attacks where tools from one server
can be used to escalate privileges or access resources in another.
"""

from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass

from mcp_sec.models import Finding, FindingCategory, FindingSeverity, MCPTool


@dataclass
class ServerContext:
    """Context information about a server and its tools."""
    server_name: str
    server_url: Optional[str]
    tools: List[MCPTool]
    permissions: List[str]
    client: Optional[str] = None


@dataclass 
class CrossOriginRisk:
    """Represents a cross-origin risk between servers."""
    source_server: str
    target_server: str
    attack_vector: str
    severity: FindingSeverity
    description: str


class CrossOriginAnalyzer:
    """Analyzes cross-origin attack vectors between MCP servers."""
    
    # Tool categories that can interact across origins
    TOOL_CATEGORIES = {
        "file_read": ["read", "get", "fetch", "load", "open", "cat", "view"],
        "file_write": ["write", "save", "create", "put", "store", "modify"],
        "execute": ["exec", "run", "eval", "spawn", "shell", "command"],
        "network": ["http", "request", "api", "webhook", "post", "send"],
        "database": ["query", "select", "insert", "update", "delete", "sql"],
        "auth": ["login", "auth", "token", "credential", "password", "key"],
    }
    
    # Known attack patterns
    ATTACK_PATTERNS = [
        {
            "name": "Credential Theft",
            "source_capabilities": ["file_read", "database"],
            "target_capabilities": ["auth"],
            "description": "Source server can read credentials and target can use them",
            "severity": FindingSeverity.HIGH
        },
        {
            "name": "Data Exfiltration",
            "source_capabilities": ["file_read", "database"],
            "target_capabilities": ["network"],
            "description": "Source server can read data and target can send it externally",
            "severity": FindingSeverity.HIGH
        },
        {
            "name": "Privilege Escalation",
            "source_capabilities": ["execute"],
            "target_capabilities": ["auth", "file_write"],
            "description": "Source server can execute commands that modify target's permissions",
            "severity": FindingSeverity.CRITICAL
        },
        {
            "name": "Tool Shadowing",
            "source_capabilities": ["file_write"],
            "target_capabilities": ["execute"],
            "description": "Source can write files that target might execute",
            "severity": FindingSeverity.MEDIUM
        },
    ]
    
    def __init__(self):
        """Initialize the cross-origin analyzer."""
        pass
    
    def analyze_cross_origin_risks(self, servers: List[ServerContext]) -> List[Finding]:
        """Analyze cross-origin risks between multiple servers.
        
        Args:
            servers: List of server contexts
            
        Returns:
            List of findings
        """
        findings = []
        
        # Categorize tools for each server
        server_capabilities = {}
        for server in servers:
            server_capabilities[server.server_name] = self._categorize_tools(server.tools)
        
        # Check each pair of servers for cross-origin risks
        for i, source_server in enumerate(servers):
            for target_server in servers[i+1:]:
                risks = self._analyze_server_pair(
                    source_server,
                    target_server,
                    server_capabilities[source_server.server_name],
                    server_capabilities[target_server.server_name]
                )
                
                for risk in risks:
                    findings.append(self._risk_to_finding(risk))
        
        # Check for tool name collisions (shadowing)
        shadowing_findings = self._check_tool_shadowing(servers)
        findings.extend(shadowing_findings)
        
        return findings
    
    def _categorize_tools(self, tools: List[MCPTool]) -> Dict[str, List[MCPTool]]:
        """Categorize tools by their capabilities.
        
        Args:
            tools: List of MCP tools
            
        Returns:
            Dictionary mapping categories to tools
        """
        categorized = {category: [] for category in self.TOOL_CATEGORIES}
        
        for tool in tools:
            tool_text = f"{tool.name} {tool.description or ''}".lower()
            
            for category, keywords in self.TOOL_CATEGORIES.items():
                if any(keyword in tool_text for keyword in keywords):
                    categorized[category].append(tool)
        
        return categorized
    
    def _analyze_server_pair(self,
                            source: ServerContext,
                            target: ServerContext,
                            source_caps: Dict[str, List[MCPTool]],
                            target_caps: Dict[str, List[MCPTool]]) -> List[CrossOriginRisk]:
        """Analyze risks between a pair of servers.
        
        Args:
            source: Source server context
            target: Target server context
            source_caps: Source server capabilities
            target_caps: Target server capabilities
            
        Returns:
            List of cross-origin risks
        """
        risks = []
        
        for pattern in self.ATTACK_PATTERNS:
            # Check if source has required capabilities
            source_has = all(
                len(source_caps.get(cap, [])) > 0
                for cap in pattern["source_capabilities"]
            )
            
            # Check if target has required capabilities
            target_has = all(
                len(target_caps.get(cap, [])) > 0
                for cap in pattern["target_capabilities"]
            )
            
            if source_has and target_has:
                risks.append(CrossOriginRisk(
                    source_server=source.server_name,
                    target_server=target.server_name,
                    attack_vector=pattern["name"],
                    severity=pattern["severity"],
                    description=pattern["description"]
                ))
        
        # Check for same-origin bypass
        if self._check_same_origin_bypass(source, target):
            risks.append(CrossOriginRisk(
                source_server=source.server_name,
                target_server=target.server_name,
                attack_vector="Same-Origin Bypass",
                severity=FindingSeverity.MEDIUM,
                description="Servers share similar names or URLs that could confuse origin checks"
            ))
        
        return risks
    
    def _check_same_origin_bypass(self, source: ServerContext, target: ServerContext) -> bool:
        """Check if servers could bypass same-origin policies.
        
        Args:
            source: Source server
            target: Target server
            
        Returns:
            True if bypass is possible
        """
        # Check for similar names
        if source.server_name and target.server_name:
            source_name = source.server_name.lower()
            target_name = target.server_name.lower()
            
            # Check for substring matches
            if (source_name in target_name or target_name in source_name) and source_name != target_name:
                return True
            
            # Check for common prefixes/suffixes
            common_patterns = ["-dev", "-prod", "-test", "-staging", "_v1", "_v2"]
            for pattern in common_patterns:
                if pattern in source_name and pattern in target_name:
                    return True
        
        # Check for similar URLs
        if source.server_url and target.server_url:
            # Extract domains
            from urllib.parse import urlparse
            source_domain = urlparse(source.server_url).netloc
            target_domain = urlparse(target.server_url).netloc
            
            # Check for subdomain relationships
            if source_domain and target_domain:
                if (source_domain in target_domain or target_domain in source_domain) and source_domain != target_domain:
                    return True
        
        return False
    
    def _check_tool_shadowing(self, servers: List[ServerContext]) -> List[Finding]:
        """Check for tool name shadowing across servers.
        
        Args:
            servers: List of server contexts
            
        Returns:
            List of findings
        """
        findings = []
        
        # Build map of tool names to servers
        tool_map: Dict[str, List[Tuple[str, MCPTool]]] = {}
        
        for server in servers:
            for tool in server.tools:
                if tool.name not in tool_map:
                    tool_map[tool.name] = []
                tool_map[tool.name].append((server.server_name, tool))
        
        # Check for collisions
        for tool_name, server_tools in tool_map.items():
            if len(server_tools) > 1:
                servers_list = [st[0] for st in server_tools]
                
                # Check if tools have different behaviors
                descriptions = [st[1].description for st in server_tools]
                schemas = [st[1].input_schema for st in server_tools]
                
                behaviors_differ = len(set(descriptions)) > 1 or len(set(str(s) for s in schemas)) > 1
                
                severity = FindingSeverity.HIGH if behaviors_differ else FindingSeverity.MEDIUM
                
                findings.append(Finding(
                    severity=severity,
                    category=FindingCategory.TOOL_CAPABILITY,
                    title=f"Tool shadowing detected for '{tool_name}'",
                    description=f"Tool '{tool_name}' exists in multiple servers: {', '.join(servers_list)}. "
                               f"{'Tools have different behaviors!' if behaviors_differ else 'Tools appear similar.'}",
                    recommendation="Use unique tool names across servers to prevent confusion and potential attacks.",
                    metadata={
                        "tool_name": tool_name,
                        "servers": servers_list,
                        "behaviors_differ": behaviors_differ
                    }
                ))
        
        return findings
    
    def _risk_to_finding(self, risk: CrossOriginRisk) -> Finding:
        """Convert a cross-origin risk to a finding.
        
        Args:
            risk: Cross-origin risk
            
        Returns:
            Finding object
        """
        return Finding(
            severity=risk.severity,
            category=FindingCategory.TOOL_CAPABILITY,
            title=f"Cross-origin {risk.attack_vector} risk",
            description=f"Potential cross-origin attack between '{risk.source_server}' and '{risk.target_server}': {risk.description}",
            recommendation="Review the necessity of these tool combinations. "
                          "Consider implementing stricter isolation between servers or limiting tool capabilities.",
            metadata={
                "source_server": risk.source_server,
                "target_server": risk.target_server,
                "attack_vector": risk.attack_vector
            }
        )
    
    def analyze_single_server(self, server: ServerContext, other_servers: List[ServerContext]) -> List[Finding]:
        """Analyze cross-origin risks for a single server against others.
        
        Args:
            server: Server to analyze
            other_servers: Other servers in the environment
            
        Returns:
            List of findings
        """
        all_servers = [server] + other_servers
        return self.analyze_cross_origin_risks(all_servers)


def detect_cross_origin_attacks(servers: List[ServerContext]) -> List[Finding]:
    """Convenience function to detect cross-origin attacks.
    
    Args:
        servers: List of server contexts
        
    Returns:
        List of findings
    """
    analyzer = CrossOriginAnalyzer()
    return analyzer.analyze_cross_origin_risks(servers)