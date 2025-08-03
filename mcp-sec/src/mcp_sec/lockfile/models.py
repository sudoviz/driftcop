"""Models for lock file management."""

from datetime import datetime
from typing import Dict, Optional
from pydantic import BaseModel, Field


class ToolDigest(BaseModel):
    """Digest information for a tool."""
    name: str
    digest: str


class LockFileEntry(BaseModel):
    """Entry in the lock file for a manifest."""
    manifest_path: str
    manifest_digest: str
    server_name: str
    version: str
    tool_digests: Dict[str, str] = Field(default_factory=dict)
    approved_at: datetime
    approved_by: Optional[str] = None
    signature: Optional[str] = None
    metadata: Dict[str, str] = Field(default_factory=dict)