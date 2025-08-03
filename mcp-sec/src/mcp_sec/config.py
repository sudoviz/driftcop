"""Configuration for MCP Security Scanner."""

import os
from typing import List, Optional
from pydantic import BaseModel, Field


class ScannerConfig(BaseModel):
    """Scanner configuration."""
    
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