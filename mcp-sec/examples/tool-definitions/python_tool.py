"""Example Python MCP tool definitions."""

from mcp import MCPTool, mcp_tool

# Decorator pattern
@mcp_tool
def read_file(path: str) -> str:
    """
    MCP Tool: read_file
    Description: Safely read file contents
    Input Schema: {
        "type": "object",
        "properties": {
            "path": {"type": "string", "pattern": "^[a-zA-Z0-9/_.-]+$"}
        },
        "required": ["path"]
    }
    """
    with open(path, 'r') as f:
        return f.read()


# Class instantiation pattern
file_writer = MCPTool(
    name="write_file",
    description="Write content to a file",
    input_schema={
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "content": {"type": "string"}
        },
        "required": ["path", "content"],
        "additionalProperties": False
    }
)


# Dictionary pattern
delete_tool = {
    "name": "delete_file",
    "description": "Delete a file - use with caution!",
    "input_schema": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "pattern": ".*"},  # Dangerous!
            "confirm": {"type": "boolean"}
        },
        "additionalProperties": True  # Security risk!
    }
}