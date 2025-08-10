"""Configuration for MCP Security Scanner."""

import os
import sys
from typing import List, Optional, Dict
from pydantic import BaseModel, Field


class DiscoveryConfig(BaseModel):
    """Configuration for MCP client discovery."""
    
    # Client paths based on platform
    client_paths: Dict[str, List[str]] = Field(default_factory=lambda: {
        "windsurf": ["~/.codeium/windsurf/mcp_config.json"],
        "cursor": ["~/.cursor/mcp.json"],
        "claude": ["~/Library/Application Support/Claude/claude_desktop_config.json"] if sys.platform == "darwin" 
                  else ["~/AppData/Roaming/Claude/claude_desktop_config.json"] if sys.platform == "win32"
                  else [],
        "vscode": ["~/.vscode/mcp.json", "~/Library/Application Support/Code/User/settings.json"] if sys.platform == "darwin"
                  else ["~/.vscode/mcp.json", "~/AppData/Roaming/Code/User/settings.json"] if sys.platform == "win32"
                  else ["~/.vscode/mcp.json", "~/.config/Code/User/settings.json"],
    })
    
    # Auto-discovery settings
    auto_discover: bool = True
    scan_all_clients: bool = False
    preferred_clients: List[str] = Field(default_factory=lambda: ["claude", "cursor", "vscode", "windsurf"])


class ScannerConfig(BaseModel):
    """Scanner configuration."""
    
    # Discovery settings
    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    
    # OpenAI settings
    openai_api_key: Optional[str] = Field(default_factory=lambda: os.getenv("OPENAI_API_KEY"))
    openai_model: str = "gpt-4-turbo-preview"
    
    # Security thresholds
    typo_similarity_threshold: float = 0.92
    max_risk_score: float = 7.0  # CI fails if total risk exceeds this
    
    # Known good MCP servers (for typosquatting detection)
    known_servers: List[str] = Field(default_factory=lambda: [
        "filesystem",
        "github", 
        "postgres",
        "sqlite",
        "slack",
        "google-drive",
        "memory",
        "puppeteer",
        "brave-search",
        "fetch"
    ])
    
    # Docker sandbox settings
    sandbox_image: str = "alpine:latest"
    sandbox_timeout_seconds: int = 30
    sandbox_memory_limit: str = "512m"
    sandbox_cpu_limit: str = "0.5"
    
    # Network allowlist for sandbox
    allowed_hosts: List[str] = Field(default_factory=lambda: [
        "vulndb.example.com",
        "api.openai.com"
    ])
    
    # Report settings
    sarif_version: str = "2.1.0"
    
    class Config:
        env_prefix = "MCP_SEC_"


config = ScannerConfig()