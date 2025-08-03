"""JavaScript/TypeScript language extractor for MCP tool definitions."""

import json
from typing import Dict, Any

try:
    from tree_sitter import Parser, Language
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False

try:
    from tree_sitter_javascript import language as js_language
    # Convert PyCapsule to Language object
    JAVASCRIPT_LANGUAGE = Language(js_language())
except ImportError:
    JAVASCRIPT_LANGUAGE = None

try:
    from tree_sitter_typescript import language_typescript
    # Convert PyCapsule to Language object
    TYPESCRIPT_LANGUAGE = Language(language_typescript())
except ImportError:
    TYPESCRIPT_LANGUAGE = None

from .base import LanguageExtractor, ExtractedTool


class JavaScriptExtractor(LanguageExtractor):
    """Extract MCP tool definitions from JavaScript code."""
    
    def _get_language(self):
        """Get the JavaScript language for tree-sitter."""
        return JAVASCRIPT_LANGUAGE
    
    def get_tool_query(self) -> str:
        """
        Query for JavaScript/TypeScript MCP tool definitions.
        
        From spec: defineTool({ name:"…", description:"…" })
        """
        return """
        (call_expression
          function: (identifier) @fn (#match? @fn "defineTool|registerTool")
          arguments: (arguments
            (object
              (pair
                (property_identifier) @key (#match? @key "name|description|inputSchema|outputSchema")
                value: (string) @val))))
        """
    
    def parse_captured_nodes(self, captures: Dict[str, Any], source_code: bytes) -> ExtractedTool:
        """Parse JavaScript-specific captures into ExtractedTool."""
        tool = ExtractedTool(name="unknown")
        
        # Process captures from simplified query pattern
        # Query captures: @fn (function name), @key (property name), @val (property value)
        if "fn" in captures and captures["fn"]:
            # Verify it's a defineTool or registerTool call
            fn_name = self._get_node_text(captures["fn"][0], source_code)
            if fn_name in ["defineTool", "registerTool"]:
                tool.line_number = self._get_node_line(captures["fn"][0])
        
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
                elif val_text.startswith("'") and val_text.endswith("'"):
                    value = val_text[1:-1]
                elif val_text.startswith('`') and val_text.endswith('`'):
                    value = val_text[1:-1]
                else:
                    value = val_text
                
                if key == "name":
                    tool.name = value
                    if tool.line_number == 0:
                        tool.line_number = self._get_node_line(keys[i])
                elif key == "description":
                    tool.description = value
                elif key == "inputSchema":
                    tool.input_schema = self._parse_js_object(val_text)
                elif key == "outputSchema":
                    tool.output_schema = self._parse_js_object(val_text)
        
        return tool
    
    def _parse_js_object(self, obj_text: str) -> Dict[str, Any]:
        """Parse a JavaScript object literal."""
        try:
            # Simple conversion from JS to JSON
            # This is a basic implementation - could be enhanced
            json_text = obj_text.replace("'", '"')
            # Remove trailing commas
            import re
            json_text = re.sub(r',\s*}', '}', json_text)
            json_text = re.sub(r',\s*]', ']', json_text)
            
            return json.loads(json_text)
        except:
            return {"raw": obj_text}
    
    def _parse_class_body(self, class_body_node, source_code: bytes, tool: ExtractedTool):
        """Extract tool metadata from class methods and properties."""
        class_text = self._get_node_text(class_body_node, source_code)
        
        # Look for getName() method
        if "getName()" in class_text or "get name()" in class_text:
            # Simple pattern matching - could be enhanced with nested query
            import re
            name_match = re.search(r'(?:getName\(\)|get name\(\))\s*{\s*return\s*["\'`]([^"\'`]+)["\'`]', class_text)
            if name_match:
                tool.name = name_match.group(1)
        
        # Look for getDescription() method
        if "getDescription()" in class_text or "get description()" in class_text:
            desc_match = re.search(r'(?:getDescription\(\)|get description\(\))\s*{\s*return\s*["\'`]([^"\'`]+)["\'`]', class_text)
            if desc_match:
                tool.description = desc_match.group(1)


class TypeScriptExtractor(JavaScriptExtractor):
    """Extract MCP tool definitions from TypeScript code."""
    
    def _get_language(self):
        """Get the TypeScript language for tree-sitter."""
        return TYPESCRIPT_LANGUAGE
    
    def get_tool_query(self) -> str:
        """
        Enhanced query for TypeScript with type annotations.
        """
        base_query = super().get_tool_query()
        
        # Add TypeScript-specific patterns
        typescript_additions = """
        ; Interface definition
        (interface_declaration
          name: (type_identifier) @interface_name (#match? @interface_name ".*Tool$")
          body: (interface_body) @interface_body)
        
        ; Type alias pattern
        (type_alias_declaration
          name: (type_identifier) @type_name
          value: (object_type
            (property_signature
              name: (property_identifier) @key1 (#eq? @key1 "name")
              type: (type_annotation (literal_type (string) @name)))
            (property_signature
              name: (property_identifier) @key2 (#eq? @key2 "description")
              type: (type_annotation (literal_type (string) @description)))?))
        
        ; Const assertion pattern
        (variable_declarator
          name: (identifier) @const_name
          value: (as_expression
            (object) @tool_object
            (template_string) @const_assertion (#eq? @const_assertion "`const`")))
        """
        
        return base_query + "\n" + typescript_additions