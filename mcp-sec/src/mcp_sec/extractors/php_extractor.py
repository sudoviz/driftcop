"""PHP language extractor for MCP tool definitions."""

import json
from typing import Dict, Any

try:
    from tree_sitter import Parser, Language
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False

try:
    from tree_sitter_php import language
    # Convert PyCapsule to Language object
    PHP_LANGUAGE = Language(language())
except ImportError:
    PHP_LANGUAGE = None

from .base import LanguageExtractor, ExtractedTool


class PHPExtractor(LanguageExtractor):
    """Extract MCP tool definitions from PHP code."""
    
    def _get_language(self):
        """Get the PHP language for tree-sitter."""
        return PHP_LANGUAGE
    
    def get_tool_query(self) -> str:
        """
        Query for PHP MCP tool definitions.
        
        From spec: ['name' => '…', 'description' => '…']
        """
        return """
        (array_creation_expression
          (array_element_initializer
            key: (string) @key (#match? @key "'name'|'description'|'inputSchema'|'outputSchema'|\\"name\\"|\"description\\"|\"inputSchema\\"|\"outputSchema\"")
            value: (string) @val))
        """
    
    def parse_captured_nodes(self, captures: Dict[str, Any], source_code: bytes) -> ExtractedTool:
        """Parse PHP-specific captures into ExtractedTool."""
        tool = ExtractedTool(name="unknown")
        
        # Process key-value pairs from array
        if "key" in captures and "val" in captures:
            keys = captures.get("key", [])
            vals = captures.get("val", [])
            
            # Pair up keys and values
            for i in range(min(len(keys), len(vals))):
                key_text = self._get_node_text(keys[i], source_code)
                val_text = self._get_node_text(vals[i], source_code)
                
                # Remove quotes from key and value
                if key_text.startswith('"') and key_text.endswith('"'):
                    key = key_text[1:-1]
                elif key_text.startswith("'") and key_text.endswith("'"):
                    key = key_text[1:-1]
                else:
                    key = key_text
                
                if val_text.startswith('"') and val_text.endswith('"'):
                    value = val_text[1:-1]
                elif val_text.startswith("'") and val_text.endswith("'"):
                    value = val_text[1:-1]
                else:
                    value = val_text
                
                if key == "name":
                    tool.name = value
                    tool.line_number = self._get_node_line(keys[i])
                elif key == "description":
                    tool.description = value
                elif key == "inputSchema":
                    tool.input_schema = self._parse_php_schema(val_text)
                elif key == "outputSchema":
                    tool.output_schema = self._parse_php_schema(val_text)
        
        return tool
    
    def _parse_php_schema(self, schema_text: str) -> Dict[str, Any]:
        """Parse a PHP schema definition (array or JSON string)."""
        # Try to parse as JSON if it looks like a JSON string
        if schema_text.startswith('[') or schema_text.startswith('{'):
            try:
                return json.loads(schema_text)
            except:
                pass
        # Otherwise return raw
        return {"raw": schema_text}