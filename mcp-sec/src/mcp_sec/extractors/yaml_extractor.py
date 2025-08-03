"""YAML language extractor for MCP tool definitions."""

import yaml
from typing import Dict, Any, List
from pathlib import Path

from .base import LanguageExtractor, ExtractedTool


class YAMLExtractor(LanguageExtractor):
    """Extract MCP tool definitions from YAML files (OpenAPI, ai-plugin.yaml)."""
    
    def __init__(self):
        """Initialize YAML extractor."""
        super().__init__()
    
    def _uses_tree_sitter(self) -> bool:
        """YAML extractor doesn't use tree-sitter."""
        return False
    
    def _get_language(self):
        """YAML doesn't need tree-sitter language - we parse directly."""
        return None
    
    def get_tool_query(self) -> str:
        """YAML doesn't use tree-sitter queries."""
        return ""
    
    def parse_captured_nodes(self, captures: Dict[str, Any], source_code: bytes) -> ExtractedTool:
        """YAML doesn't use tree-sitter node parsing."""
        raise NotImplementedError("YAML extractor doesn't use tree-sitter")
    
    def extract_tools(self, file_path: Path) -> List[ExtractedTool]:
        """Extract MCP tool definitions from YAML files."""
        try:
            # Load and parse YAML
            with open(file_path, 'r') as f:
                data = yaml.safe_load(f)
            
            if not data:
                return []
            
            tools = []
            
            # Check if it's an OpenAPI spec
            if isinstance(data, dict):
                # OpenAPI 3.x format
                if "openapi" in data and "paths" in data:
                    for path, methods in data.get("paths", {}).items():
                        if isinstance(methods, dict):
                            for method, operation in methods.items():
                                if method.lower() in ["get", "post", "put", "delete", "patch"] and isinstance(operation, dict):
                                    tool = ExtractedTool(
                                        name=operation.get("operationId", f"{method}_{path}"),
                                        description=operation.get("summary") or operation.get("description"),
                                        input_schema=self._extract_openapi_input_schema(operation),
                                        output_schema=self._extract_openapi_output_schema(operation),
                                        file_path=str(file_path),
                                        language="yaml"
                                    )
                                    tools.append(tool)
                
                # MCP manifest format in YAML
                elif "tools" in data and isinstance(data["tools"], list):
                    for tool_data in data["tools"]:
                        if isinstance(tool_data, dict) and "name" in tool_data:
                            tool = ExtractedTool(
                                name=tool_data.get("name", "unknown"),
                                description=tool_data.get("description"),
                                input_schema=tool_data.get("inputSchema") or tool_data.get("input_schema"),
                                output_schema=tool_data.get("outputSchema") or tool_data.get("output_schema"),
                                file_path=str(file_path),
                                language="yaml"
                            )
                            tools.append(tool)
                
                # AI Plugin format (ai-plugin.yaml)
                elif "schema_version" in data and "api" in data:
                    api_info = data.get("api", {})
                    if "url" in api_info:
                        # Extract from referenced OpenAPI spec
                        tool = ExtractedTool(
                            name=data.get("name_for_model", "unknown"),
                            description=data.get("description_for_model") or data.get("description_for_human"),
                            metadata={"openapi_url": api_info["url"]},
                            file_path=str(file_path),
                            language="yaml"
                        )
                        tools.append(tool)
            
            return tools
            
        except Exception as e:
            # Return empty list on parse error
            return []
    
    def _extract_openapi_input_schema(self, operation: Dict[str, Any]) -> Dict[str, Any]:
        """Extract input schema from OpenAPI operation."""
        schema = {"type": "object", "properties": {}}
        
        # Extract parameters
        for param in operation.get("parameters", []):
            if isinstance(param, dict):
                name = param.get("name")
                if name:
                    schema["properties"][name] = param.get("schema", {"type": "string"})
                    if param.get("required", False):
                        if "required" not in schema:
                            schema["required"] = []
                        schema["required"].append(name)
        
        # Extract request body
        request_body = operation.get("requestBody", {})
        if "content" in request_body:
            for content_type, content in request_body["content"].items():
                if "application/json" in content_type and "schema" in content:
                    schema["properties"]["body"] = content["schema"]
                    break
        
        return schema if schema["properties"] else None
    
    def _extract_openapi_output_schema(self, operation: Dict[str, Any]) -> Dict[str, Any]:
        """Extract output schema from OpenAPI operation."""
        responses = operation.get("responses", {})
        
        # Look for successful response (2xx)
        for status, response in responses.items():
            # Handle both string and int status codes
            status_str = str(status)
            if status_str.startswith("2") and isinstance(response, dict) and "content" in response:
                for content_type, content in response["content"].items():
                    if "application/json" in content_type and "schema" in content:
                        return content["schema"]
        
        return None