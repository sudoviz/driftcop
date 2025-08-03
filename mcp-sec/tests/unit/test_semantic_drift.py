"""Unit tests for semantic drift analyzer."""

import pytest
from unittest.mock import Mock, patch
from mcp_sec.analyzers.semantic_drift import SemanticDriftAnalyzer
from mcp_sec.models import MCPManifest, MCPTool, FindingSeverity


class TestSemanticDriftAnalyzer:
    """Test semantic drift detection functionality."""
    
    @pytest.fixture
    def analyzer(self):
        """Create a semantic drift analyzer instance."""
        return SemanticDriftAnalyzer()
    
    @pytest.fixture
    def manifest_factory(self):
        """Factory for creating test manifests."""
        def _create_manifest(name: str, description: str, tools=None):
            return MCPManifest(
                path="/test/mcp.json",
                name=name,
                version="1.0.0",
                description=description,
                tools=tools or []
            )
        return _create_manifest
    
    @pytest.fixture
    def mock_llm_response(self):
        """Mock LLM API responses."""
        def _mock_response(alignment_score=0.9, issues=None, suggestions=None):
            return {
                "choices": [{
                    "message": {
                        "content": f"""{{
                            "alignment_score": {alignment_score},
                            "issues": {issues or []},
                            "suggestions": {suggestions or []},
                            "analysis": "Test analysis"
                        }}"""
                    }
                }]
            }
        return _mock_response
    
    def test_analyze_no_api_key(self, analyzer, manifest_factory, monkeypatch):
        """Test handling when no API key is available."""
        # Ensure no API key is set
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        
        manifest = manifest_factory(
            name="test-server",
            description="A test server"
        )
        
        result = analyzer.analyze(manifest)
        
        # Should skip analysis without API key
        assert result.passed
        assert len(result.findings) == 0
        assert result.metadata.get("skipped") is True
        assert "api_key" in result.metadata.get("skip_reason", "").lower()
    
    @patch('openai.ChatCompletion.create')
    def test_analyze_with_good_alignment(self, mock_openai, analyzer, manifest_factory, mock_llm_response, monkeypatch):
        """Test analysis with good alignment between name and description."""
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        
        # Mock successful response with high alignment
        mock_openai.return_value = mock_llm_response(alignment_score=0.95)
        
        manifest = manifest_factory(
            name="weather-server",
            description="Provides weather data and forecasts",
            tools=[
                MCPTool(
                    name="get_weather",
                    description="Get current weather for a location",
                    input_schema={"type": "object"}
                ),
                MCPTool(
                    name="get_forecast",
                    description="Get weather forecast",
                    input_schema={"type": "object"}
                )
            ]
        )
        
        result = analyzer.analyze(manifest)
        
        assert result.passed
        assert len(result.findings) == 0
        assert result.metadata["alignment_score"] == 0.95
        assert result.metadata["llm_provider"] == "openai"
    
    @patch('openai.ChatCompletion.create')
    def test_analyze_with_drift(self, mock_openai, analyzer, manifest_factory, mock_llm_response, monkeypatch):
        """Test detection of semantic drift."""
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        
        # Mock response indicating drift
        mock_openai.return_value = mock_llm_response(
            alignment_score=0.4,
            issues=[
                "Server name suggests file operations but tools are for database",
                "Mismatch between declared purpose and actual functionality"
            ],
            suggestions=[
                "Rename server to 'database-server'",
                "Update description to match actual functionality"
            ]
        )
        
        manifest = manifest_factory(
            name="file-manager",
            description="Manages files and directories",
            tools=[
                MCPTool(
                    name="query_database",
                    description="Execute SQL queries",
                    input_schema={"type": "object"}
                ),
                MCPTool(
                    name="create_table",
                    description="Create database tables",
                    input_schema={"type": "object"}
                )
            ]
        )
        
        result = analyzer.analyze(manifest)
        
        assert not result.passed
        assert len(result.findings) > 0
        
        finding = result.findings[0]
        assert "semantic drift" in finding.title.lower()
        assert finding.severity == FindingSeverity.WARNING
        assert "database" in finding.description
        assert len(finding.metadata.get("suggestions", [])) > 0
    
    @patch('openai.ChatCompletion.create')
    def test_analyze_tool_drift(self, mock_openai, analyzer, manifest_factory, mock_llm_response, monkeypatch):
        """Test detection of drift in individual tools."""
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        
        # Mock response for tool-level drift
        mock_openai.return_value = mock_llm_response(
            alignment_score=0.6,
            issues=[
                "Tool 'safe_reader' has capabilities beyond reading",
                "Tool name doesn't reflect its write capabilities"
            ]
        )
        
        manifest = manifest_factory(
            name="io-server",
            description="Input/output operations server",
            tools=[
                MCPTool(
                    name="safe_reader",
                    description="Read and write files with full system access",
                    input_schema={
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "content": {"type": "string"},
                            "mode": {"type": "string", "enum": ["read", "write", "delete"]}
                        }
                    }
                )
            ]
        )
        
        result = analyzer.analyze(manifest)
        
        assert not result.passed
        findings = [f for f in result.findings if "safe_reader" in f.description]
        assert len(findings) > 0
    
    @patch('openai.ChatCompletion.create')
    def test_analyze_with_llm_error(self, mock_openai, analyzer, manifest_factory, monkeypatch):
        """Test handling of LLM API errors."""
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        
        # Mock API error
        mock_openai.side_effect = Exception("API Error")
        
        manifest = manifest_factory(
            name="test-server",
            description="Test server"
        )
        
        result = analyzer.analyze(manifest)
        
        # Should handle error gracefully
        assert not result.passed
        assert len(result.findings) == 1
        assert "error" in result.findings[0].title.lower()
        assert result.findings[0].severity == FindingSeverity.ERROR
    
    @patch('openai.ChatCompletion.create')
    def test_analyze_with_invalid_response(self, mock_openai, analyzer, manifest_factory, monkeypatch):
        """Test handling of invalid LLM responses."""
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        
        # Mock invalid response format
        mock_openai.return_value = {
            "choices": [{
                "message": {
                    "content": "This is not valid JSON"
                }
            }]
        }
        
        manifest = manifest_factory(
            name="test-server",
            description="Test server"
        )
        
        result = analyzer.analyze(manifest)
        
        # Should handle parsing error
        assert not result.passed
        assert any("parse" in f.description.lower() for f in result.findings)
    
    def test_prepare_analysis_prompt(self, analyzer, manifest_factory):
        """Test prompt preparation for LLM."""
        manifest = manifest_factory(
            name="calc-server",
            description="Mathematical calculations",
            tools=[
                MCPTool(
                    name="add",
                    description="Add two numbers",
                    input_schema={"type": "object"}
                )
            ]
        )
        
        prompt = analyzer._prepare_analysis_prompt(manifest)
        
        assert "calc-server" in prompt
        assert "Mathematical calculations" in prompt
        assert "add" in prompt
        assert "Add two numbers" in prompt
        assert "JSON" in prompt  # Should ask for JSON response
    
    def test_threshold_configuration(self, analyzer, manifest_factory, monkeypatch):
        """Test configurable alignment threshold."""
        # Test with custom threshold
        custom_analyzer = SemanticDriftAnalyzer(alignment_threshold=0.7)
        
        manifest = manifest_factory(
            name="test-server",
            description="Test server"
        )
        
        # Mock the _call_llm method to return specific alignment score
        with patch.object(custom_analyzer, '_call_llm') as mock_llm:
            mock_llm.return_value = {
                "alignment_score": 0.75,  # Above custom threshold
                "issues": [],
                "suggestions": []
            }
            
            result = custom_analyzer.analyze(manifest)
            
            assert result.passed  # 0.75 > 0.7 threshold
            assert len(result.findings) == 0
            
            # Now test with score below threshold
            mock_llm.return_value = {
                "alignment_score": 0.65,  # Below custom threshold
                "issues": ["Minor drift detected"],
                "suggestions": []
            }
            
            result = custom_analyzer.analyze(manifest)
            
            assert not result.passed  # 0.65 < 0.7 threshold
            assert len(result.findings) > 0