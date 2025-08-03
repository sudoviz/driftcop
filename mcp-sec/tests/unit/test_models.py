"""Tests for data models."""

import pytest
from mcp_sec.models import (
    Finding, FindingSeverity, FindingCategory, 
    MCPTool, MCPManifest, ScanResult, AnalysisResult
)


class TestModels:
    """Test data model classes."""
    
    def test_finding_creation(self):
        """Test creating a finding."""
        finding = Finding(
            severity=FindingSeverity.HIGH,
            category=FindingCategory.TYPOSQUATTING,
            title="Test finding",
            description="This is a test finding",
            recommendation="Fix the issue"
        )
        
        assert finding.severity == FindingSeverity.HIGH
        assert finding.category == FindingCategory.TYPOSQUATTING
        assert finding.title == "Test finding"
        assert finding.description == "This is a test finding"
        assert finding.recommendation == "Fix the issue"
    
    def test_mcp_tool_creation(self):
        """Test creating an MCP tool."""
        tool = MCPTool(
            name="test_tool",
            description="A test tool",
            input_schema={"type": "object"}
        )
        
        assert tool.name == "test_tool"
        assert tool.description == "A test tool"
        assert tool.input_schema == {"type": "object"}
        assert tool.output_schema is None
    
    def test_mcp_manifest_creation(self):
        """Test creating an MCP manifest."""
        tool = MCPTool(
            name="tool1",
            description="First tool",
            input_schema={"type": "object"}
        )
        
        manifest = MCPManifest(
            path="/test/mcp.json",
            name="test-server",
            version="1.0.0",
            description="Test server",
            tools=[tool]
        )
        
        assert manifest.path == "/test/mcp.json"
        assert manifest.name == "test-server"
        assert manifest.version == "1.0.0"
        assert manifest.description == "Test server"
        assert len(manifest.tools) == 1
        assert manifest.tools[0].name == "tool1"
    
    def test_scan_result_creation(self):
        """Test creating a scan result."""
        finding = Finding(
            severity=FindingSeverity.WARNING,
            category=FindingCategory.CONFIGURATION,
            title="Config issue",
            description="Configuration problem"
        )
        
        result = ScanResult(
            scanner_name="test_scanner",
            passed=False,
            findings=[finding],
            metadata={"test": "data"}
        )
        
        assert result.scanner_name == "test_scanner"
        assert result.passed is False
        assert len(result.findings) == 1
        assert result.findings[0].title == "Config issue"
        assert result.metadata["test"] == "data"
    
    def test_scan_result_severity_counts(self):
        """Test severity counting in scan results."""
        findings = [
            Finding(severity=FindingSeverity.CRITICAL, category=FindingCategory.VULNERABILITY, 
                   title="Critical", description="Critical issue"),
            Finding(severity=FindingSeverity.HIGH, category=FindingCategory.VULNERABILITY,
                   title="High", description="High issue"),
            Finding(severity=FindingSeverity.HIGH, category=FindingCategory.VULNERABILITY,
                   title="High 2", description="Another high issue"),
            Finding(severity=FindingSeverity.WARNING, category=FindingCategory.CONFIGURATION,
                   title="Warning", description="Warning issue"),
        ]
        
        result = ScanResult(
            scanner_name="test",
            passed=False,
            findings=findings
        )
        
        assert result.critical_count == 1
        assert result.high_count == 2
        assert result.warning_count == 1
        assert result.medium_count == 0
        assert result.low_count == 0
    
    def test_analysis_result_creation(self):
        """Test creating an analysis result."""
        result = AnalysisResult(
            analyzer_name="test_analyzer",
            passed=True,
            findings=[],
            metadata={"score": 0.95}
        )
        
        assert result.analyzer_name == "test_analyzer"
        assert result.passed is True
        assert len(result.findings) == 0
        assert result.metadata["score"] == 0.95