"""MCP Configuration Parser.

Parses various MCP client configuration formats and extracts server information.
Handles Claude, Cursor, VSCode, Windsurf, and other MCP client formats.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass
from enum import Enum

from pydantic import BaseModel, Field


class ServerType(str, Enum):
    """MCP server types."""
    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"


class MCPServer(BaseModel):
    """MCP server configuration."""
    name: str
    type: ServerType
    
    # For stdio servers
    command: Optional[str] = None
    args: Optional[List[str]] = None
    env: Optional[Dict[str, str]] = None
    
    # For HTTP/SSE servers
    url: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    
    # Additional metadata
    client: Optional[str] = None
    config_path: Optional[str] = None


class ConfigFormat(str, Enum):
    """Configuration file formats."""
    CLAUDE = "claude"
    CURSOR = "cursor"
    VSCODE = "vscode"
    WINDSURF = "windsurf"
    GENERIC = "generic"


class ConfigParser:
    """Parses MCP configuration files from various clients."""
    
    @staticmethod
    def detect_format(config: Dict[str, Any], path: Optional[Path] = None) -> ConfigFormat:
        """Detect the configuration format.
        
        Args:
            config: Configuration dictionary
            path: Optional path to help identify format
            
        Returns:
            Detected configuration format
        """
        # Check by structure
        if "mcpServers" in config:
            # Could be Claude, Cursor, or Windsurf
            if path:
                path_str = str(path).lower()
                if "claude" in path_str:
                    return ConfigFormat.CLAUDE
                elif "cursor" in path_str:
                    return ConfigFormat.CURSOR
                elif "windsurf" in path_str or "codeium" in path_str:
                    return ConfigFormat.WINDSURF
            # Default to Claude format if has mcpServers
            return ConfigFormat.CLAUDE
            
        elif "mcp" in config and isinstance(config["mcp"], dict):
            # VSCode format with mcp section
            return ConfigFormat.VSCODE
            
        elif "servers" in config:
            # Could be direct servers format
            if path and ("vscode" in str(path).lower() or "code" in str(path).lower()):
                return ConfigFormat.VSCODE
            return ConfigFormat.GENERIC
            
        return ConfigFormat.GENERIC
    
    @staticmethod
    def parse_config(config: Dict[str, Any], 
                    format: Optional[ConfigFormat] = None,
                    path: Optional[Path] = None,
                    client_name: Optional[str] = None) -> List[MCPServer]:
        """Parse configuration and extract MCP servers.
        
        Args:
            config: Configuration dictionary
            format: Optional format hint
            path: Optional configuration file path
            client_name: Optional client name
            
        Returns:
            List of MCP server configurations
        """
        if format is None:
            format = ConfigParser.detect_format(config, path)
        
        servers = []
        server_configs = ConfigParser._extract_server_configs(config, format)
        
        for server_name, server_config in server_configs.items():
            server = ConfigParser._parse_server_config(
                server_name, 
                server_config,
                client_name=client_name or format.value,
                config_path=str(path) if path else None
            )
            if server:
                servers.append(server)
                
        return servers
    
    @staticmethod
    def _extract_server_configs(config: Dict[str, Any], format: ConfigFormat) -> Dict[str, Any]:
        """Extract server configurations based on format.
        
        Args:
            config: Configuration dictionary
            format: Configuration format
            
        Returns:
            Dictionary of server configurations
        """
        if format == ConfigFormat.CLAUDE:
            return config.get("mcpServers", {})
            
        elif format in [ConfigFormat.CURSOR, ConfigFormat.WINDSURF]:
            # Try mcpServers first, then servers
            return config.get("mcpServers", config.get("servers", {}))
            
        elif format == ConfigFormat.VSCODE:
            # Check for mcp.servers or just servers
            if "mcp" in config and isinstance(config["mcp"], dict):
                return config["mcp"].get("servers", {})
            return config.get("servers", {})
            
        else:  # GENERIC
            # Try common keys
            for key in ["mcpServers", "servers", "mcp_servers"]:
                if key in config:
                    if isinstance(config[key], dict):
                        return config[key]
                    
        return {}
    
    @staticmethod
    def _parse_server_config(name: str, 
                           config: Dict[str, Any],
                           client_name: Optional[str] = None,
                           config_path: Optional[str] = None) -> Optional[MCPServer]:
        """Parse individual server configuration.
        
        Args:
            name: Server name
            config: Server configuration dictionary
            client_name: Optional client name
            config_path: Optional configuration file path
            
        Returns:
            MCPServer object or None if invalid
        """
        if not isinstance(config, dict):
            return None
            
        # Determine server type
        server_type = ConfigParser._detect_server_type(config)
        if not server_type:
            return None
            
        server = MCPServer(
            name=name,
            type=server_type,
            client=client_name,
            config_path=config_path
        )
        
        # Parse based on type
        if server_type == ServerType.STDIO:
            server.command = config.get("command")
            server.args = config.get("args", [])
            server.env = config.get("env", {})
            
        elif server_type in [ServerType.HTTP, ServerType.SSE]:
            server.url = config.get("url")
            server.headers = config.get("headers", {})
            
        return server
    
    @staticmethod
    def _detect_server_type(config: Dict[str, Any]) -> Optional[ServerType]:
        """Detect server type from configuration.
        
        Args:
            config: Server configuration dictionary
            
        Returns:
            Server type or None if cannot determine
        """
        # Check explicit type field
        if "type" in config:
            type_str = config["type"].lower()
            if type_str == "stdio":
                return ServerType.STDIO
            elif type_str == "http":
                return ServerType.HTTP
            elif type_str == "sse":
                return ServerType.SSE
                
        # Infer from fields
        if "command" in config:
            return ServerType.STDIO
        elif "url" in config:
            # Default to SSE for URL-based servers
            return ServerType.SSE
            
        return None
    
    @staticmethod
    def parse_file(path: Path, client_name: Optional[str] = None) -> List[MCPServer]:
        """Parse configuration file and extract servers.
        
        Args:
            path: Path to configuration file
            client_name: Optional client name override
            
        Returns:
            List of MCP servers
        """
        try:
            with open(path, 'r') as f:
                config = json.load(f)
                
            return ConfigParser.parse_config(
                config,
                path=path,
                client_name=client_name
            )
        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"Error parsing {path}: {e}")
            return []
    
    @staticmethod
    def validate_server(server: MCPServer) -> List[str]:
        """Validate server configuration.
        
        Args:
            server: MCP server configuration
            
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        if server.type == ServerType.STDIO:
            if not server.command:
                errors.append(f"Server '{server.name}': stdio server missing command")
                
        elif server.type in [ServerType.HTTP, ServerType.SSE]:
            if not server.url:
                errors.append(f"Server '{server.name}': {server.type} server missing URL")
            elif not (server.url.startswith("http://") or server.url.startswith("https://")):
                errors.append(f"Server '{server.name}': invalid URL format: {server.url}")
                
        return errors


def parse_all_configs(configs: List[Dict[str, Any]], 
                     paths: Optional[List[Path]] = None) -> List[MCPServer]:
    """Parse multiple configuration dictionaries.
    
    Args:
        configs: List of configuration dictionaries
        paths: Optional list of paths corresponding to configs
        
    Returns:
        Combined list of all MCP servers
    """
    all_servers = []
    parser = ConfigParser()
    
    for i, config in enumerate(configs):
        path = paths[i] if paths and i < len(paths) else None
        servers = parser.parse_config(config, path=path)
        all_servers.extend(servers)
        
    return all_servers