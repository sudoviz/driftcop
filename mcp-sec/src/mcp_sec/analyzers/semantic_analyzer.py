"""Semantic drift detection using LLM analysis."""

import json
from typing import List, Optional

import openai
from openai import OpenAI

from mcp_sec.models import Finding, FindingType, Severity, MCPTool
from mcp_sec.config import config


def check_tool_semantic_drift(tool: MCPTool) -> List[Finding]:
    """Check if tool description matches its actual capabilities."""
    findings = []
    
    # Skip if no API key configured
    if not config.openai_api_key:
        return findings
    
    try:
        # Initialize OpenAI client
        client = OpenAI(api_key=config.openai_api_key)
        
        # Prepare the analysis prompt
        analysis = _analyze_tool_drift(client, tool)
        
        if analysis and analysis.get("is_suspicious"):
            findings.append(Finding(
                category=FindingType.SEMANTIC_DRIFT,
                severity=Severity.MEDIUM,
                title=f"Semantic drift in tool '{tool.name}'",
                description=analysis.get("justification", "Tool capabilities don't match description"),
                cwe_id="CWE-601",
                recommendation="Ensure tool description accurately reflects its capabilities",
                metadata={
                    "tool_name": tool.name,
                    "analysis": analysis
                }
            ))
        
        # Check for overly broad permissions
        permission_findings = _check_tool_permissions(tool)
        findings.extend(permission_findings)
        
    except Exception as e:
        # Log error but continue - semantic analysis is optional
        print(f"Semantic analysis failed: {e}")
    
    return findings


def _analyze_tool_drift(client: OpenAI, tool: MCPTool) -> Optional[dict]:
    """Use LLM to analyze semantic drift between description and schema."""
    
    # Define the function for structured output
    functions = [{
        "name": "analyze_semantic_drift",
        "description": "Analyze if a tool's description matches its actual capabilities",
        "parameters": {
            "type": "object",
            "properties": {
                "is_suspicious": {
                    "type": "boolean",
                    "description": "True if there's semantic drift between description and capabilities"
                },
                "justification": {
                    "type": "string",
                    "description": "Explanation of why this is or isn't suspicious"
                },
                "severity": {
                    "type": "string",
                    "enum": ["low", "medium", "high"],
                    "description": "Severity of the semantic drift if suspicious"
                },
                "actual_capabilities": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of actual capabilities based on the schema"
                },
                "claimed_capabilities": {
                    "type": "array", 
                    "items": {"type": "string"},
                    "description": "List of capabilities claimed in the description"
                }
            },
            "required": ["is_suspicious", "justification"]
        }
    }]
    
    # Prepare the prompt
    prompt = f"""Analyze this MCP tool definition for semantic drift.

Tool Name: {tool.name}
Description: {tool.description}
Input Schema: {json.dumps(tool.input_schema, indent=2)}
Output Schema: {json.dumps(tool.output_schema, indent=2) if tool.output_schema else "None"}

Check if:
1. The description accurately reflects what the tool can do based on its schema
2. The tool claims to do one thing but the schema suggests it does something else
3. The schema has parameters that suggest broader capabilities than described
4. There are any security-relevant mismatches

Be especially suspicious of:
- Tools that claim to be read-only but have write/delete parameters
- Tools with generic descriptions but complex schemas
- Tools that downplay their actual capabilities
"""
    
    try:
        response = client.chat.completions.create(
            model=config.openai_model,
            messages=[
                {"role": "system", "content": "You are a security analyst examining MCP tool definitions for potential deception or misdirection."},
                {"role": "user", "content": prompt}
            ],
            functions=functions,
            function_call={"name": "analyze_semantic_drift"},
            temperature=0.1,
            max_tokens=500
        )
        
        # Extract the function call response
        if response.choices[0].message.function_call:
            return json.loads(response.choices[0].message.function_call.arguments)
        
    except Exception as e:
        print(f"LLM analysis error: {e}")
    
    return None


def _check_tool_permissions(tool: MCPTool) -> List[Finding]:
    """Check for overly broad or suspicious permissions in tool schema."""
    findings = []
    
    # Check for wildcard patterns in schema
    schema_str = json.dumps(tool.input_schema)
    
    suspicious_patterns = {
        '"pattern": ".*"': "Accepts any input pattern",
        '"additionalProperties": true': "Accepts arbitrary additional properties",
        '"maxLength": 999999': "Unusually high length limit",
        '"type": "any"': "Accepts any data type"
    }
    
    for pattern, description in suspicious_patterns.items():
        if pattern in schema_str:
            findings.append(Finding(
                category=FindingType.EXCESSIVE_PERMISSIONS,
                severity=Severity.LOW,
                title=f"Overly permissive schema in tool '{tool.name}'",
                description=f"Tool schema {description}, which may allow unintended inputs",
                cwe_id="CWE-20",
                recommendation="Tighten input validation constraints in the schema",
                metadata={"tool_name": tool.name, "pattern": pattern}
            ))
    
    # Check for command injection risks
    dangerous_params = ["command", "cmd", "exec", "script", "code", "eval"]
    param_names = _extract_param_names(tool.input_schema)
    
    for param in param_names:
        if any(danger in param.lower() for danger in dangerous_params):
            findings.append(Finding(
                category=FindingType.EXCESSIVE_PERMISSIONS,
                severity=Severity.HIGH,
                title=f"Potential command injection parameter in '{tool.name}'",
                description=f"Parameter '{param}' suggests command execution capability",
                cwe_id="CWE-78",
                recommendation="Ensure proper input validation and sandboxing for command execution",
                metadata={"tool_name": tool.name, "parameter": param}
            ))
    
    return findings


def _extract_param_names(schema: dict) -> List[str]:
    """Extract parameter names from JSON schema."""
    params = []
    
    if "properties" in schema:
        params.extend(schema["properties"].keys())
    
    # Recursively check nested schemas
    for key, value in schema.items():
        if isinstance(value, dict):
            if "properties" in value:
                params.extend(value["properties"].keys())
    
    return params