"""C# language extractor for MCP tool definitions."""

import json
from typing import Dict, Any

try:
    from tree_sitter import Parser, Language
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False

try:
    from tree_sitter_c_sharp import language
    # Convert PyCapsule to Language object
    CSHARP_LANGUAGE = Language(language())
except ImportError:
    CSHARP_LANGUAGE = None

from .base import LanguageExtractor, ExtractedTool


class CSharpExtractor(LanguageExtractor):
    """Extract MCP tool definitions from C# code."""
    
    def _get_language(self):
        """Get the C# language for tree-sitter."""
        return CSHARP_LANGUAGE
    
    def get_tool_query(self) -> str:
        """
        Query for C# MCP tool definitions.
        
        From spec: new Tool { Name = "…", Description = "…" }
        """
        return """
        (object_creation_expression
          type: (identifier) @type (#eq? @type "Tool")
          initializer: (initializer_expression
            (assignment_expression
              left: (identifier) @key (#match? @key "Name|Description|InputSchema|OutputSchema")
              right: (string_literal) @val)))
        """
    
    def parse_captured_nodes(self, captures: Dict[str, Any], source_code: bytes) -> ExtractedTool:
        """Parse C#-specific captures into ExtractedTool."""
        tool = ExtractedTool(name="unknown")
        
        # Process captures from simplified query pattern
        # Query captures: @type (Tool), @key (property name), @val (property value)
        if "type" in captures and captures["type"]:
            # Verify it's a Tool instantiation
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
                
                if key == "Name":
                    tool.name = value
                    if tool.line_number == 0:
                        tool.line_number = self._get_node_line(keys[i])
                elif key == "Description":
                    tool.description = value
                elif key == "InputSchema":
                    tool.input_schema = {"raw": val_text}
                elif key == "OutputSchema":
                    tool.output_schema = {"raw": val_text}
        
        return tool