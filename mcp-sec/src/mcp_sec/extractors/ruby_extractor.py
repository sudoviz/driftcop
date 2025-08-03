"""Ruby language extractor for MCP tool definitions."""

import json
from typing import Dict, Any

try:
    from tree_sitter import Parser, Language
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False

try:
    from tree_sitter_ruby import language
    # Convert PyCapsule to Language object
    RUBY_LANGUAGE = Language(language())
except ImportError:
    RUBY_LANGUAGE = None

from .base import LanguageExtractor, ExtractedTool


class RubyExtractor(LanguageExtractor):
    """Extract MCP tool definitions from Ruby code."""
    
    def _get_language(self):
        """Get the Ruby language for tree-sitter."""
        return RUBY_LANGUAGE
    
    def get_tool_query(self) -> str:
        """
        Query for Ruby MCP tool definitions.
        
        From spec: define_tool(name: "…", description: "…")
        """
        return """
        (method_call
          method: (identifier) @fn (#match? @fn "define_tool|register_tool")
          arguments: (argument_list
            (pair
              key: (hash_key) @key (#match? @key "name|description|input_schema|output_schema")
              value: (string) @val)))
        """
    
    def parse_captured_nodes(self, captures: Dict[str, Any], source_code: bytes) -> ExtractedTool:
        """Parse Ruby-specific captures into ExtractedTool."""
        tool = ExtractedTool(name="unknown")
        
        # Process captures from simplified query pattern
        # Query captures: @fn (method name), @key (hash key), @val (hash value)
        if "fn" in captures and captures["fn"]:
            # Verify it's a define_tool or register_tool call
            fn_name = self._get_node_text(captures["fn"][0], source_code)
            if fn_name in ["define_tool", "register_tool"]:
                tool.line_number = self._get_node_line(captures["fn"][0])
        
        # Process key-value pairs
        if "key" in captures and "val" in captures:
            keys = captures.get("key", [])
            vals = captures.get("val", [])
            
            # Pair up keys and values
            for i in range(min(len(keys), len(vals))):
                key_text = self._get_node_text(keys[i], source_code)
                val_text = self._get_node_text(vals[i], source_code)
                
                # Clean up key (remove colon)
                if key_text.endswith(':'):
                    key = key_text[:-1]
                else:
                    key = key_text.strip(':')
                
                # Remove quotes from string values
                if val_text.startswith('"') and val_text.endswith('"'):
                    value = val_text[1:-1]
                elif val_text.startswith("'") and val_text.endswith("'"):
                    value = val_text[1:-1]
                else:
                    value = val_text
                
                if key == "name":
                    tool.name = value
                    if tool.line_number == 0:
                        tool.line_number = self._get_node_line(keys[i])
                elif key == "description":
                    tool.description = value
                elif key == "input_schema":
                    tool.input_schema = self._parse_ruby_schema(val_text)
                elif key == "output_schema":
                    tool.output_schema = self._parse_ruby_schema(val_text)
        
        return tool
    
    def _parse_ruby_schema(self, schema_text: str) -> Dict[str, Any]:
        """Parse a Ruby schema definition (hash or JSON)."""
        # Ruby hashes might be in different formats
        # For now, return raw text
        return {"raw": schema_text}