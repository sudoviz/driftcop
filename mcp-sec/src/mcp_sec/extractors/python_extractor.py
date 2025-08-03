"""Python language extractor for MCP tool definitions."""

import json
import ast
from typing import Dict, Any

try:
    from tree_sitter import Parser, Language
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False

try:
    from tree_sitter_python import language
    # Convert PyCapsule to Language object
    PYTHON_LANGUAGE = Language(language())
except ImportError:
    PYTHON_LANGUAGE = None

from .base import LanguageExtractor, ExtractedTool


class PythonExtractor(LanguageExtractor):
    """Extract MCP tool definitions from Python code."""
    
    def _get_language(self):
        """Get the Python language for tree-sitter."""
        return PYTHON_LANGUAGE
    
    def get_tool_query(self) -> str:
        """
        Query for Python MCP tool definitions.
        
        From spec: register_tool(name="…", description="…")
        """
        return """
        (call
          function: (identifier) @fn (#match? @fn "register_tool|define_tool")
          arguments: (argument_list
            (keyword_argument
              name: (identifier) @key (#match? @key "name|description|input_schema|output_schema")
              value: (string) @val)))
        """
    
    def parse_captured_nodes(self, captures: Dict[str, Any], source_code: bytes) -> ExtractedTool:
        """Parse Python-specific captures into ExtractedTool."""
        tool = ExtractedTool(name="unknown")
        
        # Process captures from simplified query pattern
        # Query captures: @fn (function name), @key (parameter name), @val (parameter value)
        if "fn" in captures and captures["fn"]:
            # Verify it's a register_tool or define_tool call
            fn_name = self._get_node_text(captures["fn"][0], source_code)
            if fn_name in ["register_tool", "define_tool"]:
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
                else:
                    value = val_text
                
                if key == "name":
                    tool.name = value
                    if tool.line_number == 0:
                        tool.line_number = self._get_node_line(keys[i])
                elif key == "description":
                    tool.description = value
                elif key == "input_schema":
                    tool.input_schema = self._parse_schema(val_text)
                elif key == "output_schema":
                    tool.output_schema = self._parse_schema(val_text)
        
        return tool
    
    def _parse_schema(self, schema_text: str) -> Dict[str, Any]:
        """Parse a schema definition from Python code."""
        try:
            # Try to evaluate as Python literal
            return ast.literal_eval(schema_text)
        except:
            try:
                # Try as JSON
                return json.loads(schema_text)
            except:
                # Return raw text if parsing fails
                return {"raw": schema_text}
    
    def _parse_docstring_metadata(self, docstring: str, tool: ExtractedTool):
        """Extract MCP metadata from a docstring."""
        lines = docstring.split('\n')
        
        for i, line in enumerate(lines):
            line = line.strip()
            
            if line.startswith("MCP Tool:") or line.startswith("mcp_tool:"):
                # Extract tool name from docstring
                if i + 1 < len(lines):
                    tool.name = lines[i + 1].strip()
                    
            elif line.startswith("Description:"):
                if i + 1 < len(lines):
                    tool.description = lines[i + 1].strip()
                    
            elif line.startswith("Input Schema:"):
                # Look for JSON schema in following lines
                schema_lines = []
                j = i + 1
                while j < len(lines) and lines[j].strip().startswith(("{", "}", "[", "]", '"')):
                    schema_lines.append(lines[j])
                    j += 1
                if schema_lines:
                    try:
                        tool.input_schema = json.loads('\n'.join(schema_lines))
                    except:
                        pass
    
    def _parse_mcp_tool_args(self, args_node, source_code: bytes, tool: ExtractedTool):
        """Parse arguments from MCPTool(...) instantiation."""
        args_text = self._get_node_text(args_node, source_code)
        
        # Simple keyword argument parsing
        if "name=" in args_text:
            name_match = args_text.split("name=")[1].split(",")[0].strip().strip('"\'')
            tool.name = name_match
            
        if "description=" in args_text:
            desc_match = args_text.split("description=")[1].split(",")[0].strip().strip('"\'')
            tool.description = desc_match