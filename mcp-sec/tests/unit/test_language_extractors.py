"""Unit tests for language extractors."""

import pytest
from pathlib import Path
from mcp_sec.extractors import get_extractor, extract_from_file
from mcp_sec.extractors.python_extractor import PythonExtractor
from mcp_sec.extractors.javascript_extractor import JavaScriptExtractor
from mcp_sec.extractors.go_extractor import GoExtractor
from mcp_sec.extractors.rust_extractor import RustExtractor
from mcp_sec.extractors.java_extractor import JavaExtractor


class TestPythonExtractor:
    """Test Python language extractor."""
    
    @pytest.fixture
    def extractor(self):
        return PythonExtractor()
    
    def test_extract_register_tool(self, extractor, tmp_path):
        """Test extracting register_tool pattern."""
        code = '''
def setup_tools():
    register_tool(
        name="calculate",
        description="Perform calculations",
        input_schema={"type": "object", "properties": {"expression": {"type": "string"}}},
        output_schema={"type": "object", "properties": {"result": {"type": "number"}}}
    )
    
    define_tool(
        name="search",
        description="Search for information"
    )
'''
        file_path = tmp_path / "tools.py"
        file_path.write_text(code)
        
        tools = extractor.extract_tools(file_path)
        
        assert len(tools) == 2
        
        # Check first tool
        assert tools[0].name == "calculate"
        assert tools[0].description == "Perform calculations"
        assert tools[0].input_schema is not None
        assert tools[0].file_path == str(file_path)
        assert tools[0].language == "python"
        assert tools[0].line_number > 0
        
        # Check second tool
        assert tools[1].name == "search"
        assert tools[1].description == "Search for information"
    
    def test_query_pattern(self, extractor):
        """Test the Tree-sitter query pattern."""
        query = extractor.get_tool_query()
        assert "register_tool|define_tool" in query
        assert "@fn" in query
        assert "@key" in query
        assert "@val" in query


class TestJavaScriptExtractor:
    """Test JavaScript language extractor."""
    
    @pytest.fixture
    def extractor(self):
        return JavaScriptExtractor()
    
    def test_extract_define_tool(self, extractor, tmp_path):
        """Test extracting defineTool pattern."""
        code = '''
const tools = {
    calculator: defineTool({
        name: "calculator",
        description: "A simple calculator",
        inputSchema: {
            type: "object",
            properties: {
                a: { type: "number" },
                b: { type: "number" },
                operation: { type: "string" }
            }
        }
    }),
    
    fileReader: registerTool({
        name: "file_reader",
        description: "Read files from disk"
    })
};
'''
        file_path = tmp_path / "tools.js"
        file_path.write_text(code)
        
        tools = extractor.extract_tools(file_path)
        
        assert len(tools) == 2
        assert tools[0].name == "calculator"
        assert tools[0].description == "A simple calculator"
        assert tools[1].name == "file_reader"
        assert tools[1].description == "Read files from disk"


class TestGoExtractor:
    """Test Go language extractor."""
    
    @pytest.fixture
    def extractor(self):
        return GoExtractor()
    
    def test_extract_tool_struct(self, extractor, tmp_path):
        """Test extracting Tool struct pattern."""
        code = '''
package main

func InitTools() {
    tool1 := Tool{
        Name:        "database_query",
        Description: "Query the database",
        InputSchema: map[string]interface{}{
            "type": "object",
            "properties": map[string]interface{}{
                "query": map[string]string{"type": "string"},
            },
        },
    }
    
    tool2 := Tool{
        Name:        "api_call",
        Description: "Make API calls",
    }
}
'''
        file_path = tmp_path / "tools.go"
        file_path.write_text(code)
        
        tools = extractor.extract_tools(file_path)
        
        assert len(tools) == 2
        assert tools[0].name == "database_query"
        assert tools[0].description == "Query the database"
        assert tools[1].name == "api_call"
        assert tools[1].description == "Make API calls"


class TestRustExtractor:
    """Test Rust language extractor."""
    
    @pytest.fixture
    def extractor(self):
        return RustExtractor()
    
    def test_extract_tool_struct(self, extractor, tmp_path):
        """Test extracting Tool struct pattern."""
        code = '''
fn create_tools() -> Vec<Tool> {
    vec![
        Tool {
            name: "process_data",
            description: "Process input data",
            input_schema: json!({"type": "object"}),
        },
        Tool {
            name: "generate_report",
            description: "Generate a report",
        },
    ]
}
'''
        file_path = tmp_path / "tools.rs"
        file_path.write_text(code)
        
        tools = extractor.extract_tools(file_path)
        
        assert len(tools) == 2
        assert tools[0].name == "process_data"
        assert tools[0].description == "Process input data"
        assert tools[1].name == "generate_report"
        assert tools[1].description == "Generate a report"


class TestJavaExtractor:
    """Test Java language extractor."""
    
    @pytest.fixture
    def extractor(self):
        return JavaExtractor()
    
    def test_extract_tool_instantiation(self, extractor, tmp_path):
        """Test extracting new Tool() pattern."""
        code = '''
public class ToolRegistry {
    public void registerTools() {
        Tool calcTool = new Tool("calculator", "Perform calculations");
        tools.add(calcTool);
        
        tools.add(new Tool("converter", "Convert between units"));
    }
}
'''
        file_path = tmp_path / "ToolRegistry.java"
        file_path.write_text(code)
        
        tools = extractor.extract_tools(file_path)
        
        assert len(tools) == 2
        assert tools[0].name == "calculator"
        assert tools[0].description == "Perform calculations"
        assert tools[1].name == "converter"
        assert tools[1].description == "Convert between units"


class TestExtractorRegistry:
    """Test the extractor registry functionality."""
    
    def test_get_extractor_by_language(self):
        """Test getting extractors by language name."""
        python_extractor = get_extractor("python")
        assert isinstance(python_extractor, PythonExtractor)
        
        js_extractor = get_extractor("javascript")
        assert isinstance(js_extractor, JavaScriptExtractor)
        
        unknown_extractor = get_extractor("unknown")
        assert unknown_extractor is None
    
    def test_extract_from_file_by_extension(self, tmp_path):
        """Test automatic extractor selection based on file extension."""
        # Python file
        py_file = tmp_path / "test.py"
        py_file.write_text('register_tool(name="test", description="Test tool")')
        
        tools = extract_from_file(py_file)
        assert len(tools) == 1
        assert tools[0].language == "python"
        
        # JavaScript file
        js_file = tmp_path / "test.js"
        js_file.write_text('defineTool({name: "test", description: "Test tool"})')
        
        tools = extract_from_file(js_file)
        assert len(tools) == 1
        assert tools[0].language == "javascript"
    
    def test_unsupported_file_extension(self, tmp_path):
        """Test handling of unsupported file extensions."""
        unknown_file = tmp_path / "test.xyz"
        unknown_file.write_text("some content")
        
        tools = extract_from_file(unknown_file)
        assert len(tools) == 0