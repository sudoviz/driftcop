"""Go language extractor for MCP tool definitions."""

import json
from typing import Dict, Any

try:
    from tree_sitter import Parser, Language
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False

try:
    from tree_sitter_go import language
    # Convert PyCapsule to Language object
    GO_LANGUAGE = Language(language())
except ImportError:
    GO_LANGUAGE = None

from .base import LanguageExtractor, ExtractedTool


class GoExtractor(LanguageExtractor):
    """Extract MCP tool definitions from Go code."""
    
    def _get_language(self):
        """Get the Go language for tree-sitter."""
        return GO_LANGUAGE
    
    def get_tool_query(self) -> str:
        """
        Query for Go MCP tool definitions.
        
        From spec: Tool{Name:"…", Description:"…"}
        """
        return """
        (composite_literal
          type: (type_identifier) @type (#eq? @type "Tool")
          body: (literal_value
            (keyed_element
              key: (field_identifier) @key (#match? @key "Name|Description|InputSchema|OutputSchema")
              value: (basic_literal) @val)))
        """
    
    def parse_captured_nodes(self, captures: Dict[str, Any], source_code: bytes) -> ExtractedTool:
        """Parse Go-specific captures into ExtractedTool."""
        tool = ExtractedTool(name="unknown")
        
        # Process captures from simplified query pattern
        # Query captures: @type (Tool), @key (field name), @val (field value)
        if "type" in captures and captures["type"]:
            # Verify it's a Tool struct literal
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
                
                # Remove quotes from string values (Go uses double quotes)
                if val_text.startswith('"') and val_text.endswith('"'):
                    value = val_text[1:-1]
                elif val_text.startswith('`') and val_text.endswith('`'):
                    # Raw string literal
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
                    # Parse Go struct/map literal for schema
                    tool.input_schema = {"raw": val_text}
                elif key == "OutputSchema":
                    tool.output_schema = {"raw": val_text}
        
        return tool
    
    def _parse_struct_literal(self, literal_node, source_code: bytes, tool: ExtractedTool):
        """Parse a Go struct literal for tool fields."""
        literal_text = self._get_node_text(literal_node, source_code)
        
        # Parse field assignments
        lines = literal_text.split('\n')
        for line in lines:
            line = line.strip()
            
            if 'Name:' in line:
                name_value = line.split('Name:')[1].strip().rstrip(',').strip('"')
                tool.name = name_value
                
            elif 'Description:' in line:
                desc_value = line.split('Description:')[1].strip().rstrip(',').strip('"')
                tool.description = desc_value
                
            elif 'InputSchema:' in line:
                # Extract schema - this is simplified
                schema_start = line.find('{')
                if schema_start >= 0:
                    # Would need more sophisticated parsing for nested structs
                    tool.input_schema = {"raw": line[schema_start:]}
    
    def _parse_struct_fields(self, fields_node, source_code: bytes, tool: ExtractedTool):
        """Parse struct field definitions looking for tags."""
        fields_text = self._get_node_text(fields_node, source_code)
        
        # Look for struct tags that might contain MCP metadata
        import re
        
        # Find fields with json tags
        name_match = re.search(r'Name\s+string\s+`json:"name"[^`]*`', fields_text)
        if name_match:
            tool.metadata["has_name_field"] = True
            
        desc_match = re.search(r'Description\s+string\s+`json:"description"[^`]*`', fields_text)
        if desc_match:
            tool.metadata["has_description_field"] = True
            
        # Look for mcp tags
        mcp_tags = re.findall(r'`mcp:"([^"]+)"[^`]*`', fields_text)
        if mcp_tags:
            tool.metadata["mcp_tags"] = mcp_tags