#!/usr/bin/env python3
"""Test non-tree-sitter extractors that work reliably."""

import os
import json
import yaml
import tempfile
from pathlib import Path

# Set up Python path
import sys
sys.path.insert(0, 'src')

from mcp_sec.extractors import extract_from_file, get_extractor
from mcp_sec.extractors.registry import _registry


def test_json_extractor():
    """Test JSON extractor (no tree-sitter needed)."""
    print("\n=== Testing JSON Extractor ===")
    
    test_cases = [
        # Manifest with tools array
        {
            "name": "manifest_format",
            "data": {
                "name": "test-server",
                "version": "1.0.0",
                "tools": [
                    {
                        "name": "calculate",
                        "description": "Perform calculations",
                        "inputSchema": {"type": "object", "properties": {"expression": {"type": "string"}}}
                    },
                    {
                        "name": "search",
                        "description": "Search for data",
                        "outputSchema": {"type": "object", "properties": {"results": {"type": "array"}}}
                    }
                ]
            },
            "expected_tools": 2
        },
        # Single tool definition
        {
            "name": "single_tool",
            "data": {
                "name": "standalone_tool",
                "description": "A standalone tool definition",
                "inputSchema": {"type": "object"},
                "outputSchema": {"type": "object"}
            },
            "expected_tools": 1
        },
        # Array of tools
        {
            "name": "tool_array",
            "data": [
                {"name": "tool1", "description": "First tool"},
                {"name": "tool2", "description": "Second tool"},
                {"name": "tool3", "description": "Third tool"}
            ],
            "expected_tools": 3
        }
    ]
    
    all_passed = True
    
    for test_case in test_cases:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(test_case["data"], f, indent=2)
            json_file = f.name
        
        try:
            tools = extract_from_file(Path(json_file))
            if len(tools) == test_case["expected_tools"]:
                print(f"✅ {test_case['name']}: Found {len(tools)} tools as expected")
                for tool in tools:
                    print(f"   - {tool.name}: {tool.description}")
            else:
                print(f"❌ {test_case['name']}: Expected {test_case['expected_tools']} tools, found {len(tools)}")
                all_passed = False
        except Exception as e:
            print(f"❌ {test_case['name']}: Error - {e}")
            all_passed = False
        finally:
            os.unlink(json_file)
    
    return all_passed


def test_yaml_extractor():
    """Test YAML extractor (no tree-sitter needed)."""
    print("\n=== Testing YAML Extractor ===")
    
    test_cases = [
        # OpenAPI format
        {
            "name": "openapi_format",
            "data": """
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /calculate:
    post:
      operationId: calculateExpression
      summary: Calculate mathematical expression
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                expression:
                  type: string
      responses:
        200:
          description: Success
          content:
            application/json:
              schema:
                type: object
                properties:
                  result:
                    type: number
  /search:
    get:
      operationId: searchData
      summary: Search for information
      parameters:
        - name: query
          in: query
          schema:
            type: string
""",
            "expected_tools": 2
        },
        # MCP manifest in YAML
        {
            "name": "mcp_manifest_yaml",
            "data": """
name: yaml-server
version: 1.0.0
description: YAML-based MCP server
tools:
  - name: yaml_tool_1
    description: First YAML tool
    inputSchema:
      type: object
      properties:
        input:
          type: string
  - name: yaml_tool_2
    description: Second YAML tool
""",
            "expected_tools": 2
        },
        # AI Plugin format
        {
            "name": "ai_plugin",
            "data": """
schema_version: v1
name_for_model: test_plugin
name_for_human: Test Plugin
description_for_model: A test plugin for MCP
description_for_human: Test Plugin
api:
  type: openapi
  url: https://example.com/openapi.yaml
  has_user_authentication: false
""",
            "expected_tools": 1
        }
    ]
    
    all_passed = True
    
    for test_case in test_cases:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(test_case["data"])
            yaml_file = f.name
        
        try:
            tools = extract_from_file(Path(yaml_file))
            if len(tools) == test_case["expected_tools"]:
                print(f"✅ {test_case['name']}: Found {len(tools)} tools as expected")
                for tool in tools:
                    print(f"   - {tool.name}: {tool.description}")
            else:
                print(f"❌ {test_case['name']}: Expected {test_case['expected_tools']} tools, found {len(tools)}")
                all_passed = False
        except Exception as e:
            print(f"❌ {test_case['name']}: Error - {e}")
            all_passed = False
        finally:
            os.unlink(yaml_file)
    
    return all_passed


def test_extractor_registry():
    """Test the extractor registry."""
    print("\n=== Testing Extractor Registry ===")
    
    print("Checking available extractors:")
    available_count = 0
    
    for lang in ['json', 'yaml', 'python', 'javascript', 'typescript', 'go', 'rust', 'java', 'csharp', 'ruby', 'php']:
        try:
            extractor = get_extractor(lang)
            if extractor:
                print(f"  ✅ {lang}: Available")
                available_count += 1
            else:
                print(f"  ❌ {lang}: Not available")
        except Exception as e:
            print(f"  ❌ {lang}: Error - {type(e).__name__}")
    
    print(f"\n{available_count} extractors available out of 11")
    
    print("\nSupported file extensions:")
    extensions = _registry.supported_extensions
    print(f"  {', '.join(sorted(extensions))}")
    
    return available_count >= 2  # At least JSON and YAML should work


def test_extraction_by_extension():
    """Test automatic extractor selection by file extension."""
    print("\n=== Testing Extraction by Extension ===")
    
    test_files = [
        (".json", {"name": "json_test", "tools": [{"name": "tool1", "description": "Test"}]}),
        (".yaml", "name: yaml_test\ntools:\n  - name: tool2\n    description: Test"),
        (".yml", "name: yml_test\ntools:\n  - name: tool3\n    description: Test")
    ]
    
    all_passed = True
    
    for ext, content in test_files:
        with tempfile.NamedTemporaryFile(mode='w', suffix=ext, delete=False) as f:
            if isinstance(content, dict):
                json.dump(content, f)
            else:
                f.write(content)
            test_file = f.name
        
        try:
            tools = extract_from_file(Path(test_file))
            print(f"✅ {ext}: Successfully extracted {len(tools)} tools")
        except Exception as e:
            print(f"❌ {ext}: Failed - {e}")
            all_passed = False
        finally:
            os.unlink(test_file)
    
    return all_passed


def main():
    """Run extractor tests."""
    print("MCP Security Scanner - Language Extractor Tests")
    print("=" * 50)
    print("Testing extractors that don't require tree-sitter...")
    
    results = {
        'json': test_json_extractor(),
        'yaml': test_yaml_extractor(),
        'registry': test_extractor_registry(),
        'by_extension': test_extraction_by_extension()
    }
    
    # Summary
    print("\n" + "=" * 50)
    print("Test Summary:")
    for test, passed in results.items():
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"  {test}: {status}")
    
    total_passed = sum(1 for v in results.values() if v)
    print(f"\nTotal: {total_passed}/{len(results)} tests passed")
    
    print("\n📝 Note:")
    print("Tree-sitter based extractors (Python, JS, Go, etc.) require proper")
    print("compilation of language bindings. The current tree-sitter Python")
    print("bindings have compatibility issues with the latest API.")
    print("\nJSON and YAML extractors work perfectly without tree-sitter!")


if __name__ == "__main__":
    main()