"""Java language extractor for MCP tool definitions."""

import json
from typing import Dict, Any

try:
    from tree_sitter import Parser, Language
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False

try:
    from tree_sitter_java import language
    # Convert PyCapsule to Language object
    JAVA_LANGUAGE = Language(language())
except ImportError:
    JAVA_LANGUAGE = None

from .base import LanguageExtractor, ExtractedTool


class JavaExtractor(LanguageExtractor):
    """Extract MCP tool definitions from Java code."""
    
    def _get_language(self):
        """Get the Java language for tree-sitter."""
        return JAVA_LANGUAGE
    
    def get_tool_query(self) -> str:
        """
        Query for Java MCP tool definitions.
        
        From spec: new Tool("…", "…")
        """
        return """
        (object_creation_expression
          type: (type_identifier) @type (#eq? @type "Tool")
          arguments: (argument_list
            (string_literal) @name
            (string_literal) @description))
        """
    
    def parse_captured_nodes(self, captures: Dict[str, Any], source_code: bytes) -> ExtractedTool:
        """Parse Java-specific captures into ExtractedTool."""
        tool = ExtractedTool(name="unknown")
        
        # Process captures from simplified query pattern
        # Query captures: @type (Tool), @name (first argument), @description (second argument)
        if "type" in captures and captures["type"]:
            # Verify it's a Tool instantiation
            type_name = self._get_node_text(captures["type"][0], source_code)
            if type_name == "Tool":
                tool.line_number = self._get_node_line(captures["type"][0])
        
        # Extract name (first argument)
        if "name" in captures and captures["name"]:
            name_text = self._get_node_text(captures["name"][0], source_code)
            # Remove quotes from string literal
            if name_text.startswith('"') and name_text.endswith('"'):
                tool.name = name_text[1:-1]
            else:
                tool.name = name_text
        
        # Extract description (second argument)
        if "description" in captures and captures["description"]:
            desc_text = self._get_node_text(captures["description"][0], source_code)
            # Remove quotes from string literal
            if desc_text.startswith('"') and desc_text.endswith('"'):
                tool.description = desc_text[1:-1]
            else:
                tool.description = desc_text
        
        return tool
    
    def _parse_class_body(self, body_node, source_code: bytes, tool: ExtractedTool):
        """Parse Java class body for tool metadata."""
        body_text = self._get_node_text(body_node, source_code)
        
        import re
        
        # Look for getName() method
        name_match = re.search(r'public\s+String\s+getName\(\)\s*\{\s*return\s+"([^"]+)"', body_text)
        if name_match:
            tool.name = name_match.group(1)
            
        # Look for getDescription() method
        desc_match = re.search(r'public\s+String\s+getDescription\(\)\s*\{\s*return\s+"([^"]+)"', body_text)
        if desc_match:
            tool.description = desc_match.group(1)
            
        # Look for annotated fields
        field_matches = re.findall(r'@ToolField\([^)]*\)\s*private\s+\w+\s+(\w+)', body_text)
        if field_matches:
            tool.metadata["fields"] = field_matches
    
    def _parse_constructor_args(self, args_node, source_code: bytes, tool: ExtractedTool):
        """Parse constructor arguments."""
        args_text = self._get_node_text(args_node, source_code)
        
        # Simple positional argument parsing
        args = [arg.strip().strip('"') for arg in args_text.split(',')]
        
        if len(args) >= 1 and args[0]:
            tool.name = args[0]
        if len(args) >= 2 and args[1]:
            tool.description = args[1]