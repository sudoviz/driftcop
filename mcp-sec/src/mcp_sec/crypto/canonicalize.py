"""Canonicalization utilities for deterministic hashing."""

import re
import unicodedata
from typing import Any, Dict, Union
import json


def canonicalize_text(text: str) -> str:
    """
    Canonicalize text for deterministic comparison.
    
    Steps:
    1. NFC Unicode normalization
    2. Strip HTML/Markdown formatting
    3. Collapse whitespace
    4. Trim leading/trailing whitespace
    """
    if not text:
        return ""
    
    # Step 1: NFC Unicode normalization
    text = unicodedata.normalize('NFC', text)
    
    # Step 2: Strip common HTML tags
    text = re.sub(r'<[^>]+>', '', text)
    
    # Step 3: Strip Markdown formatting
    # Remove bold/italic
    text = re.sub(r'\*{1,2}([^\*]+)\*{1,2}', r'\1', text)
    text = re.sub(r'_{1,2}([^_]+)_{1,2}', r'\1', text)
    
    # Remove headers
    text = re.sub(r'^#{1,6}\s+', '', text, flags=re.MULTILINE)
    
    # Remove links but keep text
    text = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', text)
    
    # Remove inline code
    text = re.sub(r'`([^`]+)`', r'\1', text)
    
    # Remove code blocks
    text = re.sub(r'```[^`]*```', '', text, flags=re.DOTALL)
    
    # Step 4: Collapse whitespace
    text = re.sub(r'\s+', ' ', text)
    
    # Step 5: Trim
    text = text.strip()
    
    return text


def canonicalize_json(data: Union[Dict[str, Any], str]) -> bytes:
    """
    Create canonical JSON representation.
    
    Returns canonical bytes suitable for hashing.
    """
    if isinstance(data, str):
        data = json.loads(data)
    
    # Recursively canonicalize string values
    canonical_data = _canonicalize_json_values(data)
    
    # Create deterministic JSON with sorted keys
    canonical_json = json.dumps(
        canonical_data,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=True
    )
    
    return canonical_json.encode('utf-8')


def _canonicalize_json_values(obj: Any) -> Any:
    """Recursively canonicalize string values in JSON structure."""
    if isinstance(obj, dict):
        return {k: _canonicalize_json_values(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_canonicalize_json_values(item) for item in obj]
    elif isinstance(obj, str):
        # Canonicalize string values
        return canonicalize_text(obj)
    else:
        return obj


def canonicalize_schema(schema: Dict[str, Any]) -> Dict[str, Any]:
    """
    Canonicalize a JSON schema for deterministic hashing.
    
    This includes:
    - Sorting all keys
    - Normalizing descriptions
    - Removing comments
    - Standardizing whitespace
    """
    if not isinstance(schema, dict):
        return schema
    
    canonical = {}
    
    for key in sorted(schema.keys()):
        value = schema[key]
        
        # Skip comment fields
        if key in ['$comment', 'comment']:
            continue
        
        if key == 'description' and isinstance(value, str):
            # Canonicalize description text
            canonical[key] = canonicalize_text(value)
        elif isinstance(value, dict):
            canonical[key] = canonicalize_schema(value)
        elif isinstance(value, list):
            canonical[key] = [
                canonicalize_schema(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            canonical[key] = value
    
    return canonical


def create_canonical_tool_representation(tool: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a canonical representation of an MCP tool.
    
    This ensures consistent hashing regardless of formatting differences.
    """
    canonical = {
        "name": tool.get("name", ""),
        "description": canonicalize_text(tool.get("description", ""))
    }
    
    if "input_schema" in tool and tool["input_schema"]:
        canonical["input_schema"] = canonicalize_schema(tool["input_schema"])
    
    if "output_schema" in tool and tool["output_schema"]:
        canonical["output_schema"] = canonicalize_schema(tool["output_schema"])
    
    return canonical