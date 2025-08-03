"""JSON language extractor for MCP tool definitions."""

import json
from typing import Dict, Any, List
from pathlib import Path

from .base import LanguageExtractor, ExtractedTool


class JSONExtractor(LanguageExtractor):
    """Extract MCP tool definitions from JSON files (manifests, tools/list)."""
    
    def __init__(self):
        """Initialize JSON extractor."""
        super().__init__()
    
    def _uses_tree_sitter(self) -> bool:
        """JSON extractor doesn't use tree-sitter."""
        return False
    
    def _get_language(self):
        """JSON doesn't need tree-sitter language - we parse directly."""
        return None
    
    def get_tool_query(self) -> str:
        """JSON doesn't use tree-sitter queries."""
        return ""
    
    def parse_captured_nodes(self, captures: Dict[str, Any], source_code: bytes) -> ExtractedTool:
        """JSON doesn't use tree-sitter node parsing."""
        raise NotImplementedError("JSON extractor doesn't use tree-sitter")
    
    def extract_tools(self, file_path: Path) -> List[ExtractedTool]:
        """Extract MCP tool definitions from JSON files."""
        try:
            # Load and parse JSON
            data = json.loads(file_path.read_text())
            tools = []
            
            # Check if it's a manifest with tools array
            if isinstance(data, dict):
                if "tools" in data and isinstance(data["tools"], list):
                    # MCP manifest format
                    for tool_data in data["tools"]:
                        if isinstance(tool_data, dict) and "name" in tool_data:
                            tool = ExtractedTool(
                                name=tool_data.get("name", "unknown"),
                                description=tool_data.get("description"),
                                input_schema=tool_data.get("inputSchema") or tool_data.get("input_schema"),
                                output_schema=tool_data.get("outputSchema") or tool_data.get("output_schema"),
                                file_path=str(file_path),
                                language="json"
                            )
                            tools.append(tool)
                
                # Single tool definition
                elif "name" in data and ("inputSchema" in data or "input_schema" in data):
                    tool = ExtractedTool(
                        name=data.get("name", "unknown"),
                        description=data.get("description"),
                        input_schema=data.get("inputSchema") or data.get("input_schema"),
                        output_schema=data.get("outputSchema") or data.get("output_schema"),
                        file_path=str(file_path),
                        language="json"
                    )
                    tools.append(tool)
            
            # Array of tools
            elif isinstance(data, list):
                for tool_data in data:
                    if isinstance(tool_data, dict) and "name" in tool_data:
                        tool = ExtractedTool(
                            name=tool_data.get("name", "unknown"),
                            description=tool_data.get("description"),
                            input_schema=tool_data.get("inputSchema") or tool_data.get("input_schema"),
                            output_schema=tool_data.get("outputSchema") or tool_data.get("output_schema"),
                            file_path=str(file_path),
                            language="json"
                        )
                        tools.append(tool)
            
            return tools
            
        except Exception as e:
            # Return empty list on parse error
            return []