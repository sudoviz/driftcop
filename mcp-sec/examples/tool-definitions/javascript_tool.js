// Example JavaScript MCP tool definitions

const { MCPServer } = require('@mcp/server');

// Object literal pattern
const searchTool = {
  name: "search_files",
  description: "Search for files by pattern",
  inputSchema: {
    type: "object",
    properties: {
      pattern: { type: "string", pattern: ".*" },
      directory: { type: "string" }
    },
    required: ["pattern"],
    additionalProperties: false
  }
};

// Method call pattern
server.addTool({
  name: "execute_command",
  description: "Execute a shell command",
  inputSchema: {
    type: "object",
    properties: {
      command: { type: "string" },
      args: { type: "array", items: { type: "string" } }
    }
  }
});

// Class-based pattern
class DatabaseTool extends MCPTool {
  getName() {
    return "query_database";
  }
  
  getDescription() {
    return "Execute SQL queries";
  }
  
  getInputSchema() {
    return {
      type: "object",
      properties: {
        query: { type: "string" },
        params: { type: "array" }
      }
    };
  }
}

// Export pattern
export const apiTool = {
  name: "call_api",
  description: "Make HTTP API calls",
  inputSchema: {
    type: "object",
    properties: {
      url: { type: "string", format: "uri" },
      method: { type: "string", enum: ["GET", "POST", "PUT", "DELETE"] },
      body: { type: "object", additionalProperties: true }
    }
  }
};