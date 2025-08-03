"""Rust language extractor for MCP tool definitions."""

import json
from typing import Dict, Any

try:
    from tree_sitter import Parser, Language
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False

try:
    from tree_sitter_rust import language
    # Convert PyCapsule to Language object
    RUST_LANGUAGE = Language(language())
except ImportError:
    RUST_LANGUAGE = None

from .base import LanguageExtractor, ExtractedTool


class RustExtractor(LanguageExtractor):
    """Extract MCP tool definitions from Rust code."""
    
    def _get_language(self):
        """Get the Rust language for tree-sitter."""
        return RUST_LANGUAGE
    
    def get_tool_query(self) -> str:
        """
        Query for Rust MCP tool definitions.
        
        From spec: Tool { name: "…", description: "…" }
        """
        return """
        (struct_expression
          name: (type_identifier) @type (#eq? @type "Tool")
          body: (field_initializer_list
            (field_initializer
              field: (field_identifier) @key (#match? @key "name|description|input_schema|output_schema")
              value: (string_literal) @val)))
        """
    
    def parse_captured_nodes(self, captures: Dict[str, Any], source_code: bytes) -> ExtractedTool:
        """Parse Rust-specific captures into ExtractedTool."""
        tool = ExtractedTool(name="unknown")
        
        # Process captures from simplified query pattern
        # Query captures: @type (Tool), @key (field name), @val (field value)
        if "type" in captures and captures["type"]:
            # Verify it's a Tool struct
            type_name = self._get_node_text(captures["type"][0], source_code)
            if type_name == "Tool":
                tool.line_number = self._get_node_line(captures["type"][0])
        
        # Process key-value pairs
        if "key" in captures and "val" in captures:
            keys = captures.get("key", [])
            vals = captures.get("val", [])
            
            # Pair up keys and values
            for i in range(min(len(keys), len(vals))):
                key = self._get_node_text(keys[i], source_code)
                val_text = self._get_node_text(vals[i], source_code)
                
                # Remove quotes from string values
                if val_text.startswith('"') and val_text.endswith('"'):
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
                    tool.input_schema = self._parse_rust_value(val_text)
                elif key == "output_schema":
                    tool.output_schema = self._parse_rust_value(val_text)
        
        return tool
    
    def _parse_rust_value(self, val_text: str) -> Dict[str, Any]:
        """Parse Rust value literals."""
        # Handle serde_json::json! macro
        if "json!" in val_text:
            # Extract JSON from macro
            start = val_text.find('{')
            if start >= 0:
                try:
                    return json.loads(val_text[start:])
                except:
                    pass
        
        return {"raw": val_text}
    
    def _parse_field_initializers(self, init_list, source_code: bytes, tool: ExtractedTool):
        """Parse field initializers in a struct literal."""
        list_text = self._get_node_text(init_list, source_code)
        
        # Simple pattern matching for field: value pairs
        import re
        
        name_match = re.search(r'name:\s*"([^"]+)"', list_text)
        if name_match:
            tool.name = name_match.group(1)
            
        desc_match = re.search(r'description:\s*"([^"]+)"', list_text)
        if desc_match:
            tool.description = desc_match.group(1)
    
    def _parse_impl_body(self, impl_body, source_code: bytes, tool: ExtractedTool):
        """Extract tool metadata from impl blocks."""
        impl_text = self._get_node_text(impl_body, source_code)
        
        # Look for methods returning tool metadata
        if "fn name(" in impl_text:
            import re
            name_match = re.search(r'fn name\([^)]*\)\s*->\s*[^{]+\{[^"]*"([^"]+)"', impl_text)
            if name_match:
                tool.name = name_match.group(1)
                
        if "fn description(" in impl_text:
            desc_match = re.search(r'fn description\([^)]*\)\s*->\s*[^{]+\{[^"]*"([^"]+)"', impl_text)
            if desc_match:
                tool.description = desc_match.group(1)
    
    def _parse_macro_args(self, macro_args, source_code: bytes, tool: ExtractedTool):
        """Parse arguments to tool definition macros."""
        args_text = self._get_node_text(macro_args, source_code)
        
        # Parse macro arguments
        if "name:" in args_text:
            import re
            name_match = re.search(r'name:\s*"([^"]+)"', args_text)
            if name_match:
                tool.name = name_match.group(1)
                
        if "description:" in args_text:
            desc_match = re.search(r'description:\s*"([^"]+)"', args_text)
            if desc_match:
                tool.description = desc_match.group(1)