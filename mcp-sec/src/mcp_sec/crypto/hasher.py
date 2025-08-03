"""Tool and manifest hashing for version tracking."""

import hashlib
import json
from typing import Dict, Any, List
from datetime import datetime

from mcp_sec.models import MCPTool, MCPManifest


def compute_tool_hash(tool) -> str:
    """
    Compute a deterministic hash of a tool's metadata.
    
    This creates an immutable fingerprint of the tool definition
    that can be used to detect changes.
    """
    # Create a canonical representation
    # Handle both MCPTool and ExtractedTool objects
    if hasattr(tool, 'dict'):
        # MCPTool object
        canonical = {
            "name": tool.name,
            "description": tool.description,
            "input_schema": _canonicalize_schema(tool.input_schema),
            "output_schema": _canonicalize_schema(tool.output_schema) if tool.output_schema else None
        }
    else:
        # ExtractedTool object
        canonical = {
            "name": tool.name,
            "description": tool.description,
            "input_schema": _canonicalize_schema(tool.input_schema) if tool.input_schema else None,
            "output_schema": _canonicalize_schema(tool.output_schema) if tool.output_schema else None
        }
    
    # Sort keys and use separators for deterministic output
    canonical_json = json.dumps(canonical, sort_keys=True, separators=(',', ':'))
    
    # Use SHA-256 for the hash
    return hashlib.sha256(canonical_json.encode()).hexdigest()


def compute_manifest_hash(manifest: MCPManifest) -> str:
    """
    Compute a deterministic hash of the entire manifest.
    
    This provides a version identifier for the complete MCP server definition.
    """
    # Create canonical representation
    canonical = {
        "name": manifest.name,
        "version": manifest.version,
        "description": manifest.description,
        "author": manifest.author,
        "repository": manifest.repository,
        "permissions": sorted(manifest.permissions) if manifest.permissions else [],
        "tools": []
    }
    
    # Add tool hashes in sorted order
    tool_hashes = []
    for tool in manifest.tools:
        tool_hash = compute_tool_hash(tool)
        tool_hashes.append({
            "name": tool.name,
            "hash": tool_hash
        })
    
    canonical["tools"] = sorted(tool_hashes, key=lambda x: x["name"])
    
    # Generate manifest hash
    canonical_json = json.dumps(canonical, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical_json.encode()).hexdigest()


def compute_manifest_version_id(manifest: MCPManifest, timestamp: datetime = None) -> str:
    """
    Generate a version ID that includes hash and timestamp.
    
    Format: {manifest_hash}-{timestamp}
    """
    if timestamp is None:
        timestamp = datetime.utcnow()
    
    manifest_hash = compute_manifest_hash(manifest)
    timestamp_str = timestamp.strftime("%Y%m%d%H%M%S")
    
    return f"{manifest_hash[:16]}-{timestamp_str}"


def _canonicalize_schema(schema: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a canonical representation of a JSON schema.
    
    This ensures consistent hashing regardless of key order.
    """
    if not isinstance(schema, dict):
        return schema
    
    canonical = {}
    for key in sorted(schema.keys()):
        value = schema[key]
        if isinstance(value, dict):
            canonical[key] = _canonicalize_schema(value)
        elif isinstance(value, list):
            canonical[key] = [
                _canonicalize_schema(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            canonical[key] = value
    
    return canonical


def generate_tool_changelog(old_tool: MCPTool, new_tool: MCPTool) -> Dict[str, Any]:
    """
    Generate a detailed changelog between two versions of a tool.
    """
    old_hash = compute_tool_hash(old_tool)
    new_hash = compute_tool_hash(new_tool)
    
    if old_hash == new_hash:
        return {"changed": False, "hash": old_hash}
    
    changes = {
        "changed": True,
        "old_hash": old_hash,
        "new_hash": new_hash,
        "changes": []
    }
    
    # Check what changed
    if old_tool.name != new_tool.name:
        changes["changes"].append({
            "field": "name",
            "old": old_tool.name,
            "new": new_tool.name
        })
    
    if old_tool.description != new_tool.description:
        changes["changes"].append({
            "field": "description",
            "old": old_tool.description,
            "new": new_tool.description
        })
    
    # Deep comparison of schemas
    old_input_canonical = _canonicalize_schema(old_tool.input_schema)
    new_input_canonical = _canonicalize_schema(new_tool.input_schema)
    
    if old_input_canonical != new_input_canonical:
        changes["changes"].append({
            "field": "input_schema",
            "type": "schema_change",
            "details": _compare_schemas(old_input_canonical, new_input_canonical)
        })
    
    return changes


def _compare_schemas(old_schema: Dict[str, Any], new_schema: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Compare two schemas and return detailed differences."""
    differences = []
    
    # Check for added keys
    for key in new_schema:
        if key not in old_schema:
            differences.append({
                "type": "added",
                "path": key,
                "value": new_schema[key]
            })
    
    # Check for removed keys
    for key in old_schema:
        if key not in new_schema:
            differences.append({
                "type": "removed",
                "path": key,
                "value": old_schema[key]
            })
    
    # Check for modified values
    for key in old_schema:
        if key in new_schema and old_schema[key] != new_schema[key]:
            differences.append({
                "type": "modified",
                "path": key,
                "old_value": old_schema[key],
                "new_value": new_schema[key]
            })
    
    return differences