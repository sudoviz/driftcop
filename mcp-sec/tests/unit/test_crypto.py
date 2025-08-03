"""Unit tests for cryptographic functionality."""

import json
import pytest
from mcp_sec.crypto.canonicalize import canonicalize_text, canonicalize_json
from mcp_sec.crypto.hash import compute_digest, compute_tool_digest, compute_manifest_digest
from mcp_sec.models import MCPTool


class TestCanonicalization:
    """Test text and JSON canonicalization."""
    
    def test_canonicalize_text_unicode(self):
        """Test Unicode normalization."""
        # Different representations of é
        text1 = "café"  # Single character é
        text2 = "café"  # e + combining acute accent
        
        canon1 = canonicalize_text(text1)
        canon2 = canonicalize_text(text2)
        
        assert canon1 == canon2
    
    def test_canonicalize_text_whitespace(self):
        """Test whitespace normalization."""
        text = "  Multiple   spaces\n\nand\tlines  "
        canonicalized = canonicalize_text(text)
        
        assert canonicalized == "Multiple spaces and lines"
    
    def test_canonicalize_text_html_markdown(self):
        """Test HTML/Markdown stripping."""
        text = "This is **bold** and <em>italic</em> text"
        canonicalized = canonicalize_text(text)
        
        assert "**" not in canonicalized
        assert "<em>" not in canonicalized
        assert "bold" in canonicalized
        assert "italic" in canonicalized
    
    def test_canonicalize_json_key_order(self):
        """Test JSON key ordering."""
        json1 = {"b": 2, "a": 1, "c": 3}
        json2 = {"a": 1, "c": 3, "b": 2}
        
        canon1 = canonicalize_json(json1)
        canon2 = canonicalize_json(json2)
        
        assert canon1 == canon2
    
    def test_canonicalize_json_nested(self):
        """Test nested JSON canonicalization."""
        json_data = {
            "tools": [
                {"name": "tool1", "description": "Test"},
                {"description": "Test", "name": "tool2"}
            ],
            "metadata": {
                "version": "1.0",
                "author": "test"
            }
        }
        
        canonicalized = canonicalize_json(json_data)
        
        # Should be deterministic bytes
        assert isinstance(canonicalized, bytes)
        # Convert to string for checking
        canon_str = canonicalized.decode('utf-8')
        # Keys should be sorted
        assert canon_str.index('"author"') < canon_str.index('"version"')
    
    def test_canonicalize_json_unicode_values(self):
        """Test JSON with Unicode values."""
        json_data = {
            "name": "café",
            "description": "naïve résumé"
        }
        
        canonicalized = canonicalize_json(json_data)
        canon_str = canonicalized.decode('utf-8')
        
        # Should handle Unicode properly
        assert "caf" in canon_str  # After canonicalization


class TestHashing:
    """Test hashing functionality."""
    
    def test_compute_digest_string(self):
        """Test computing digest of string."""
        digest1 = compute_digest("test content")
        digest2 = compute_digest("test content")
        digest3 = compute_digest("different content")
        
        # Same content should produce same digest
        assert digest1 == digest2
        # Different content should produce different digest
        assert digest1 != digest3
        # Should be hex string
        assert all(c in "0123456789abcdef" for c in digest1)
    
    def test_compute_digest_dict(self):
        """Test computing digest of dictionary."""
        data = {"key": "value", "number": 42}
        digest = compute_digest(data)
        
        assert isinstance(digest, str)
        assert len(digest) == 64  # SHA-256 hex digest
    
    def test_compute_tool_digest(self):
        """Test computing tool digest."""
        tool = MCPTool(
            name="test_tool",
            description="A test tool",
            input_schema={"type": "object"},
            output_schema={"type": "object"}
        )
        
        digest1 = compute_tool_digest(tool)
        digest2 = compute_tool_digest(tool)
        
        assert digest1 == digest2
        
        # Change tool and verify digest changes
        tool.description = "Modified description"
        digest3 = compute_tool_digest(tool)
        
        assert digest3 != digest1
    
    def test_compute_manifest_digest(self):
        """Test computing manifest digest."""
        manifest_data = {
            "name": "test-server",
            "version": "1.0.0",
            "description": "Test server",
            "tools": [
                {
                    "name": "tool1",
                    "description": "First tool",
                    "inputSchema": {"type": "object"}
                }
            ]
        }
        
        digest1 = compute_manifest_digest(manifest_data)
        digest2 = compute_manifest_digest(manifest_data)
        
        assert digest1 == digest2
        
        # Order shouldn't matter for tools
        manifest_data["tools"].append({
            "name": "tool2",
            "description": "Second tool"
        })
        
        digest3 = compute_manifest_digest(manifest_data)
        assert digest3 != digest1
    
    def test_digest_stability(self):
        """Test digest stability across different data types."""
        # String and bytes of same content should match
        assert compute_digest("test") == compute_digest(b"test")
        
        # Different data types should produce different digests
        digests = [
            compute_digest("test"),
            compute_digest({"test": "value"}),
            compute_digest(["test"]),
            compute_digest(123),
            compute_digest("different"),
        ]
        
        # All except the duplicate should be unique
        assert len(set(digests)) == len(digests)
    
    def test_compute_tool_digest_with_dict(self):
        """Test computing digest from tool dictionary."""
        tool_dict = {
            "name": "test_tool",
            "description": "A test tool",
            "inputSchema": {"type": "object"}
        }
        
        digest = compute_tool_digest(tool_dict)
        assert isinstance(digest, str)
        assert len(digest) == 64