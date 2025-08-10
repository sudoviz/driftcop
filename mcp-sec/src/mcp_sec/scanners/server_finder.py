"""MCP Server Finder.

Auto-discovers and enumerates all MCP servers configured on the system.
Combines client discovery with configuration parsing to provide a unified view.
"""

import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

from mcp_sec.models import Finding, FindingCategory, FindingSeverity, ScanResult
from mcp_sec.scanners.client_discovery import ClientDiscovery, DiscoveredConfig
from mcp_sec.scanners.config_parser import ConfigParser, MCPServer
from mcp_sec.config import config


@dataclass 
class ServerInfo:
    """Complete information about a discovered MCP server."""
    server: MCPServer
    client: str
    config_path: Path
    raw_config: Dict
    is_running: bool = False
    is_reachable: bool = False
    metadata: Dict = None
    

class ServerFinder:
    """Finds and analyzes all MCP servers on the system."""
    
    def __init__(self):
        """Initialize the server finder."""
        self.discovery = ClientDiscovery()
        self.parser = ConfigParser()
        self.servers: List[ServerInfo] = []
        self.servers_by_name: Dict[str, List[ServerInfo]] = {}
        
    def find_all_servers(self) -> List[ServerInfo]:
        """Find all MCP servers across all clients.
        
        Returns:
            List of discovered server information
        """
        self.servers = []
        self.servers_by_name = {}
        
        # Discover all configurations
        configs = self.discovery.discover_configs()
        
        for config in configs:
            # Parse servers from this configuration
            servers = self.parser.parse_config(
                config.raw_config,
                path=config.config_path,
                client_name=config.client_name
            )
            
            # Create ServerInfo for each server
            for server in servers:
                server_info = ServerInfo(
                    server=server,
                    client=config.client_name,
                    config_path=config.config_path,
                    raw_config=config.servers.get(server.name, {}),
                    metadata={}
                )
                
                self.servers.append(server_info)
                
                # Index by name for duplicate detection
                if server.name not in self.servers_by_name:
                    self.servers_by_name[server.name] = []
                self.servers_by_name[server.name].append(server_info)
                
        return self.servers
    
    def find_servers_by_client(self, client_name: str) -> List[ServerInfo]:
        """Find all servers for a specific client.
        
        Args:
            client_name: Name of the client (claude, cursor, vscode, windsurf)
            
        Returns:
            List of servers for that client
        """
        return [s for s in self.servers if s.client == client_name]
    
    def find_servers_by_type(self, server_type: str) -> List[ServerInfo]:
        """Find all servers of a specific type.
        
        Args:
            server_type: Type of server (stdio, http, sse)
            
        Returns:
            List of servers of that type
        """
        return [s for s in self.servers if s.server.type == server_type]
    
    def find_duplicate_servers(self) -> Dict[str, List[ServerInfo]]:
        """Find servers with the same name across different clients.
        
        Returns:
            Dictionary mapping server names to list of duplicate configs
        """
        duplicates = {}
        for name, servers in self.servers_by_name.items():
            if len(servers) > 1:
                duplicates[name] = servers
        return duplicates
    
    def analyze_servers(self) -> List[Finding]:
        """Analyze discovered servers for security issues.
        
        Returns:
            List of security findings
        """
        findings = []
        
        # Check for duplicates
        duplicates = self.find_duplicate_servers()
        for server_name, duplicate_servers in duplicates.items():
            clients = list(set(s.client for s in duplicate_servers))
            
            # Check if configurations are identical
            configs_match = True
            first_config = duplicate_servers[0].raw_config
            for server_info in duplicate_servers[1:]:
                if server_info.raw_config != first_config:
                    configs_match = False
                    break
            
            severity = FindingSeverity.INFO if configs_match else FindingSeverity.MEDIUM
            
            findings.append(Finding(
                severity=severity,
                category=FindingCategory.CONFIGURATION,
                title=f"Duplicate server '{server_name}' in multiple clients",
                description=f"Server '{server_name}' is configured in {len(clients)} clients: {', '.join(clients)}. "
                           f"Configurations {'match' if configs_match else 'differ'}.",
                recommendation="Review configurations to ensure consistency or use unique names." if not configs_match
                              else "Consider if duplicate configuration is intentional.",
                metadata={
                    "server_name": server_name,
                    "clients": clients,
                    "configs_match": configs_match
                }
            ))
        
        # Check for suspicious patterns in stdio servers
        stdio_servers = self.find_servers_by_type("stdio")
        for server_info in stdio_servers:
            findings.extend(self._analyze_stdio_server(server_info))
        
        # Check for insecure URLs
        url_servers = [s for s in self.servers if s.server.url]
        for server_info in url_servers:
            findings.extend(self._analyze_url_server(server_info))
        
        return findings
    
    def _analyze_stdio_server(self, server_info: ServerInfo) -> List[Finding]:
        """Analyze a stdio server for security issues.
        
        Args:
            server_info: Server information
            
        Returns:
            List of findings
        """
        findings = []
        server = server_info.server
        
        if not server.command:
            return findings
            
        # Suspicious command patterns
        suspicious_patterns = [
            ("rm ", "contains file removal command", FindingSeverity.HIGH),
            ("del ", "contains file deletion command", FindingSeverity.HIGH),
            ("format ", "contains format command", FindingSeverity.HIGH),
            ("curl ", "downloads external content", FindingSeverity.MEDIUM),
            ("wget ", "downloads external content", FindingSeverity.MEDIUM),
            ("eval ", "uses eval command", FindingSeverity.HIGH),
            ("exec ", "uses exec command", FindingSeverity.MEDIUM),
            ("/tmp/", "uses temporary directory", FindingSeverity.LOW),
            ("~/Downloads/", "uses downloads directory", FindingSeverity.MEDIUM),
        ]
        
        command_lower = server.command.lower()
        for pattern, description, severity in suspicious_patterns:
            if pattern in command_lower:
                findings.append(Finding(
                    severity=severity,
                    category=FindingCategory.CONFIGURATION,
                    title=f"Suspicious command in server '{server.name}'",
                    description=f"Server command {description}: {server.command}",
                    recommendation="Review the command to ensure it's safe and expected. "
                                  "Consider using absolute paths and avoiding dangerous operations.",
                    file_path=str(server_info.config_path),
                    metadata={
                        "server_name": server.name,
                        "client": server_info.client,
                        "command": server.command,
                        "pattern": pattern
                    }
                ))
        
        # Check for running with elevated privileges
        if "sudo " in command_lower or "runas " in command_lower:
            findings.append(Finding(
                severity=FindingSeverity.HIGH,
                category=FindingCategory.PERMISSIONS,
                title=f"Server '{server.name}' runs with elevated privileges",
                description=f"Server command requests elevated privileges: {server.command}",
                recommendation="Avoid running MCP servers with sudo/admin privileges unless absolutely necessary.",
                file_path=str(server_info.config_path),
                metadata={
                    "server_name": server.name,
                    "client": server_info.client,
                    "command": server.command
                }
            ))
        
        return findings
    
    def _analyze_url_server(self, server_info: ServerInfo) -> List[Finding]:
        """Analyze a URL-based server for security issues.
        
        Args:
            server_info: Server information
            
        Returns:
            List of findings
        """
        findings = []
        server = server_info.server
        
        if not server.url:
            return findings
            
        url = server.url.lower()
        
        # Check for insecure HTTP
        if url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
            findings.append(Finding(
                severity=FindingSeverity.MEDIUM,
                category=FindingCategory.NETWORK_ANOMALY,
                title=f"Server '{server.name}' uses insecure HTTP",
                description=f"Server uses unencrypted HTTP connection: {server.url}",
                recommendation="Use HTTPS for secure communication, especially for external servers.",
                file_path=str(server_info.config_path),
                metadata={
                    "server_name": server.name,
                    "client": server_info.client,
                    "url": server.url
                }
            ))
        
        # Check for suspicious domains
        suspicious_domains = [
            ".tk", ".ml", ".ga", ".cf",  # Free domains often used for malicious purposes
            ".onion", ".i2p",  # Dark web
            "ngrok.io", "localtunnel.me",  # Tunneling services
        ]
        
        for domain in suspicious_domains:
            if domain in url:
                findings.append(Finding(
                    severity=FindingSeverity.HIGH,
                    category=FindingCategory.NETWORK_ANOMALY,
                    title=f"Server '{server.name}' uses suspicious domain",
                    description=f"Server URL contains suspicious domain '{domain}': {server.url}",
                    recommendation="Verify the server URL is legitimate and from a trusted source.",
                    file_path=str(server_info.config_path),
                    metadata={
                        "server_name": server.name,
                        "client": server_info.client,
                        "url": server.url,
                        "suspicious_domain": domain
                    }
                ))
        
        # Check for IP addresses instead of domains
        import re
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.search(ip_pattern, server.url) and "127.0.0.1" not in server.url and "localhost" not in server.url:
            findings.append(Finding(
                severity=FindingSeverity.LOW,
                category=FindingCategory.NETWORK_ANOMALY,
                title=f"Server '{server.name}' uses IP address instead of domain",
                description=f"Server URL uses direct IP address: {server.url}",
                recommendation="Consider using domain names for better security and flexibility.",
                file_path=str(server_info.config_path),
                metadata={
                    "server_name": server.name,
                    "client": server_info.client,
                    "url": server.url
                }
            ))
        
        return findings
    
    async def check_server_connectivity(self, server_info: ServerInfo) -> bool:
        """Check if a server is reachable.
        
        Args:
            server_info: Server information
            
        Returns:
            True if server is reachable
        """
        # This is a placeholder for actual connectivity checking
        # Would need to implement actual MCP client connection logic
        # For now, just mark as not checked
        return False
    
    def get_summary(self) -> Dict:
        """Get a summary of discovered servers.
        
        Returns:
            Summary dictionary
        """
        return {
            "total_servers": len(self.servers),
            "clients": list(set(s.client for s in self.servers)),
            "server_types": {
                "stdio": len(self.find_servers_by_type("stdio")),
                "http": len(self.find_servers_by_type("http")),
                "sse": len(self.find_servers_by_type("sse"))
            },
            "duplicate_servers": len(self.find_duplicate_servers()),
            "servers_by_client": {
                client: len(self.find_servers_by_client(client))
                for client in set(s.client for s in self.servers)
            }
        }


def discover_and_scan_all() -> Tuple[List[ServerInfo], List[Finding]]:
    """Convenience function to discover and scan all MCP servers.
    
    Returns:
        Tuple of (list of servers, list of findings)
    """
    finder = ServerFinder()
    servers = finder.find_all_servers()
    findings = finder.analyze_servers()
    
    # Also run discovery's built-in scanning
    discovery_findings = finder.discovery.scan_discovered_configs()
    findings.extend(discovery_findings)
    
    return servers, findings