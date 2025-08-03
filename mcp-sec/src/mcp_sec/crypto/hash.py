"""Hashing utilities for MCP security."""

import hashlib
import json
from typing import Any, Dict, Union

from mcp_sec.crypto.canonicalize import canonicalize_json, canonicalize_text
from mcp_sec.models import MCPTool


def compute_digest(data: Union[str, bytes, Dict[str, Any], int, list]) -> str:
    """Compute SHA-256 digest of data."""
    if isinstance(data, bytes):
        content = data
    elif isinstance(data, str):
        content = data.encode('utf-8')
    elif isinstance(data, (dict, list)):
        # Canonicalize JSON data (already returns bytes)
        content = canonicalize_json(data)
    else:
        # Convert other types to string
        content = str(data).encode('utf-8')
    
    return hashlib.sha256(content).hexdigest()


def compute_tool_digest(tool: Union[MCPTool, Dict[str, Any]]) -> str:
    """Compute digest of an MCP tool definition."""
    if isinstance(tool, MCPTool):
        # Convert to dict for consistent hashing
        tool_data = {
            "name": tool.name,
            "description": canonicalize_text(tool.description),
            "input_schema": tool.input_schema,
            "output_schema": tool.output_schema
        }
    else:
        # Assume it's already a dict
        tool_data = {
            "name": tool.get("name", ""),
            "description": canonicalize_text(tool.get("description", "")),
            "input_schema": tool.get("inputSchema") or tool.get("input_schema", {}),
            "output_schema": tool.get("outputSchema") or tool.get("output_schema")
        }
    
    # Remove None values
    tool_data = {k: v for k, v in tool_data.items() if v is not None}
    
    return compute_digest(tool_data)


def compute_manifest_digest(manifest_data: Dict[str, Any]) -> str:
    """Compute digest of a manifest."""
    # Normalize the manifest data
    normalized = {
        "name": manifest_data.get("name", ""),
        "version": manifest_data.get("version", ""),
        "description": canonicalize_text(manifest_data.get("description", "")),
        "tools": []
    }
    
    # Sort tools by name for consistent ordering
    tools = manifest_data.get("tools", [])
    sorted_tools = sorted(tools, key=lambda t: t.get("name", ""))
    
    # Add tool digests
    for tool in sorted_tools:
        normalized["tools"].append({
            "name": tool.get("name", ""),
            "digest": compute_tool_digest(tool)
        })
    
    return compute_digest(normalized)