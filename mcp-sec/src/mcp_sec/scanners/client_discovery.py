"""MCP Client Configuration Discovery.

Discovers MCP configurations from various clients like Claude, Cursor, VSCode, and Windsurf.
Auto-detection capabilities for comprehensive security scanning.
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

from mcp_sec.models import Finding, FindingCategory, FindingSeverity
from mcp_sec.config import config


@dataclass
class DiscoveredConfig:
    """Represents a discovered MCP configuration."""
    client_name: str
    config_path: Path
    servers: Dict[str, Dict]
    raw_config: Dict
    

class ClientDiscovery:
    """Discovers MCP configurations from various clients."""
    
    def __init__(self):
        """Initialize the client discovery with platform-specific paths."""
        self.config = config.discovery
        self.discovered_configs: List[DiscoveredConfig] = []
        
    def get_client_paths(self) -> Dict[str, List[str]]:
        """Get client paths based on current platform."""
        return self.config.client_paths
    
    def get_all_config_paths(self) -> List[Tuple[str, str]]:
        """Get all configuration paths to check.
        
        Returns:
            List of tuples (client_name, path)
        """
        paths = []
        for client, client_paths in self.get_client_paths().items():
            if not self.config.scan_all_clients and client not in self.config.preferred_clients:
                continue
            for path in client_paths:
                paths.append((client, path))
        return paths
    
    def discover_configs(self) -> List[DiscoveredConfig]:
        """Discover all MCP configurations on the system.
        
        Returns:
            List of discovered configurations
        """
        self.discovered_configs = []
        
        for client_name, path_str in self.get_all_config_paths():
            path = Path(os.path.expanduser(path_str))
            
            if not path.exists():
                continue
                
            try:
                config = self._parse_config_file(path, client_name)
                if config:
                    self.discovered_configs.append(config)
            except Exception as e:
                # Log but don't fail on individual config parse errors
                print(f"Warning: Failed to parse {client_name} config at {path}: {e}")
                
        return self.discovered_configs
    
    def _parse_config_file(self, path: Path, client_name: str) -> Optional[DiscoveredConfig]:
        """Parse a configuration file based on client type.
        
        Args:
            path: Path to configuration file
            client_name: Name of the client (claude, cursor, vscode, windsurf)
            
        Returns:
            DiscoveredConfig if successful, None otherwise
        """
        try:
            with open(path, 'r') as f:
                raw_config = json.load(f)
            
            servers = self._extract_servers(raw_config, client_name)
            
            if servers:
                return DiscoveredConfig(
                    client_name=client_name,
                    config_path=path,
                    servers=servers,
                    raw_config=raw_config
                )
        except json.JSONDecodeError as e:
            print(f"Invalid JSON in {path}: {e}")
        except Exception as e:
            print(f"Error reading {path}: {e}")
            
        return None
    
    def _extract_servers(self, config: Dict, client_name: str) -> Dict[str, Dict]:
        """Extract MCP server configurations from client config.
        
        Args:
            config: Raw configuration dictionary
            client_name: Name of the client
            
        Returns:
            Dictionary of server configurations
        """
        servers = {}
        
        if client_name == "claude":
            # Claude uses mcpServers key
            servers = config.get("mcpServers", {})
            
        elif client_name in ["cursor", "windsurf"]:
            # Cursor and Windsurf use mcpServers or servers key
            servers = config.get("mcpServers", config.get("servers", {}))
            
        elif client_name == "vscode":
            # VSCode can have mcp.servers or just servers
            if "mcp" in config and isinstance(config["mcp"], dict):
                servers = config["mcp"].get("servers", {})
            else:
                servers = config.get("servers", {})
                
        return servers
    
    def get_server_urls(self) -> List[str]:
        """Get all discovered server URLs.
        
        Returns:
            List of server URLs (for HTTP/SSE servers)
        """
        urls = []
        for config in self.discovered_configs:
            for server_name, server_config in config.servers.items():
                if isinstance(server_config, dict):
                    if "url" in server_config:
                        urls.append(server_config["url"])
        return urls
    
    def get_stdio_servers(self) -> List[Dict]:
        """Get all discovered stdio servers.
        
        Returns:
            List of stdio server configurations
        """
        stdio_servers = []
        for config in self.discovered_configs:
            for server_name, server_config in config.servers.items():
                if isinstance(server_config, dict):
                    if "command" in server_config:
                        stdio_servers.append({
                            "name": server_name,
                            "client": config.client_name,
                            "config": server_config
                        })
        return stdio_servers
    
    def scan_discovered_configs(self) -> List[Finding]:
        """Scan discovered configurations for basic issues.
        
        Returns:
            List of security findings
        """
        findings = []
        
        # Check for duplicate server names across clients
        server_names = {}
        for config in self.discovered_configs:
            for server_name in config.servers.keys():
                if server_name not in server_names:
                    server_names[server_name] = []
                server_names[server_name].append(config.client_name)
        
        for server_name, clients in server_names.items():
            if len(clients) > 1:
                findings.append(Finding(
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.CONFIGURATION,
                    title=f"Server '{server_name}' configured in multiple clients",
                    description=f"The MCP server '{server_name}' is configured in: {', '.join(clients)}. "
                               f"This may be intentional but could lead to confusion.",
                    recommendation="Ensure consistent configuration across clients or use unique names.",
                    metadata={"server_name": server_name, "clients": clients}
                ))
        
        # Check for suspicious server commands
        for config in self.discovered_configs:
            for server_name, server_config in config.servers.items():
                if isinstance(server_config, dict) and "command" in server_config:
                    command = server_config["command"]
                    suspicious_patterns = [
                        ("rm ", "contains removal command"),
                        ("curl ", "downloads external content"),
                        ("wget ", "downloads external content"),
                        ("/tmp/", "uses temporary directory"),
                        ("eval ", "uses eval command"),
                        ("exec ", "uses exec command"),
                    ]
                    
                    for pattern, description in suspicious_patterns:
                        if pattern in command:
                            findings.append(Finding(
                                severity=FindingSeverity.MEDIUM,
                                category=FindingCategory.CONFIGURATION,
                                title=f"Suspicious command in server '{server_name}'",
                                description=f"Server command {description}: {command}",
                                recommendation="Review the command to ensure it's safe and expected.",
                                file_path=str(config.config_path),
                                metadata={
                                    "server_name": server_name,
                                    "client": config.client_name,
                                    "command": command
                                }
                            ))
        
        return findings


def discover_all_configs() -> List[DiscoveredConfig]:
    """Convenience function to discover all MCP configurations.
    
    Returns:
        List of discovered configurations
    """
    discovery = ClientDiscovery()
    return discovery.discover_configs()


def get_client_from_path(path: str) -> Optional[str]:
    """Get client name from a configuration path.
    
    Args:
        path: Configuration file path
        
    Returns:
        Client name or None if not recognized
    """
    path_str = str(path).lower()
    
    if "claude" in path_str:
        return "claude"
    elif "cursor" in path_str:
        return "cursor"
    elif "vscode" in path_str or "code" in path_str:
        return "vscode"
    elif "windsurf" in path_str or "codeium" in path_str:
        return "windsurf"
    
    return None