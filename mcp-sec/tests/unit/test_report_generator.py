"""Unit tests for report generation."""

import json
import pytest
from datetime import datetime
from pathlib import Path
from mcp_sec.reports.generator import ReportGenerator
from mcp_sec.models import ScanResult, Finding, FindingSeverity, FindingCategory


class TestReportGenerator:
    """Test report generation functionality."""
    
    @pytest.fixture
    def generator(self):
        """Create a report generator instance."""
        return ReportGenerator()
    
    @pytest.fixture
    def sample_results(self):
        """Create sample scan results for testing."""
        return [
            ScanResult(
                scanner_name="manifest",
                passed=False,
                findings=[
                    Finding(
                        severity=FindingSeverity.HIGH,
                        category=FindingCategory.SCHEMA_VALIDATION,
                        title="Missing required field",
                        description="The manifest is missing the required 'version' field",
                        recommendation="Add a version field to the manifest",
                        metadata={
                            "field": "version",
                            "file": "/test/mcp.json"
                        }
                    ),
                    Finding(
                        severity=FindingSeverity.WARNING,
                        category=FindingCategory.CONFIGURATION,
                        title="Dangerous tool name",
                        description="Tool name 'execute_command' suggests dangerous functionality",
                        recommendation="Review tool functionality and consider renaming",
                        metadata={
                            "tool_name": "execute_command"
                        }
                    )
                ],
                metadata={
                    "manifest_path": "/test/mcp.json",
                    "server_name": "test-server",
                    "scan_duration": 0.123
                }
            ),
            ScanResult(
                scanner_name="typosquatting",
                passed=True,
                findings=[],
                metadata={
                    "checks_performed": 5
                }
            ),
            ScanResult(
                scanner_name="workspace",
                passed=False,
                findings=[
                    Finding(
                        severity=FindingSeverity.HIGH,
                        category=FindingCategory.CODE_PATTERN,
                        title="Dangerous code pattern detected",
                        description="Found usage of eval() function",
                        recommendation="Replace eval() with safer alternatives",
                        file_path="/test/src/main.py",
                        line_number=42,
                        metadata={
                            "code_snippet": "result = eval(user_input)"
                        }
                    )
                ],
                metadata={
                    "files_scanned": 10,
                    "patterns_checked": 15
                }
            )
        ]
    
    def test_generate_markdown_report(self, generator, sample_results):
        """Test Markdown report generation."""
        report = generator.generate(sample_results, format="markdown")
        
        assert isinstance(report, str)
        assert "# MCP Security Scan Report" in report
        assert "## Summary" in report
        assert "## Findings by Severity" in report
        
        # Check statistics
        assert "Total Scanners: 3" in report
        assert "Failed: 2" in report
        assert "High: 2" in report
        assert "Warning: 1" in report
        
        # Check specific findings
        assert "Missing required field" in report
        assert "execute_command" in report
        assert "eval()" in report
        
        # Check recommendations
        assert "Add a version field" in report
        assert "safer alternatives" in report
    
    def test_generate_json_report(self, generator, sample_results):
        """Test JSON report generation."""
        report = generator.generate(sample_results, format="json")
        
        # Should be valid JSON
        report_data = json.loads(report)
        
        assert "summary" in report_data
        assert "scanners" in report_data
        assert "findings" in report_data
        assert "metadata" in report_data
        
        # Check summary
        summary = report_data["summary"]
        assert summary["total_scanners"] == 3
        assert summary["passed"] == 1
        assert summary["failed"] == 2
        assert summary["total_findings"] == 3
        assert summary["findings_by_severity"]["high"] == 2
        assert summary["findings_by_severity"]["warning"] == 1
        
        # Check findings structure
        assert len(report_data["findings"]) == 3
        finding = report_data["findings"][0]
        assert "severity" in finding
        assert "title" in finding
        assert "description" in finding
        assert "scanner" in finding
    
    def test_generate_sarif_report(self, generator, sample_results):
        """Test SARIF report generation."""
        report = generator.generate(sample_results, format="sarif")
        
        # Should be valid JSON (SARIF is JSON-based)
        sarif_data = json.loads(report)
        
        # Check SARIF structure
        assert sarif_data["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        assert sarif_data["version"] == "2.1.0"
        assert "runs" in sarif_data
        
        run = sarif_data["runs"][0]
        assert run["tool"]["driver"]["name"] == "mcp-sec"
        assert "rules" in run["tool"]["driver"]
        assert "results" in run
        
        # Check results
        results = run["results"]
        assert len(results) == 3
        
        # Check specific result
        result = results[0]
        assert "ruleId" in result
        assert "level" in result
        assert "message" in result
        assert "locations" in result
    
    def test_sarif_location_mapping(self, generator, sample_results):
        """Test SARIF location information for code findings."""
        report_data = json.loads(generator.generate(sample_results, format="sarif"))
        
        # Find the eval() finding
        results = report_data["runs"][0]["results"]
        eval_result = next(r for r in results if "eval()" in r["message"]["text"])
        
        # Check location information
        assert len(eval_result["locations"]) > 0
        location = eval_result["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "/test/src/main.py"
        assert location["region"]["startLine"] == 42
    
    def test_empty_results(self, generator):
        """Test report generation with no results."""
        empty_results = []
        
        # Markdown
        md_report = generator.generate(empty_results, format="markdown")
        assert "No scanners were run" in md_report
        
        # JSON
        json_report = json.loads(generator.generate(empty_results, format="json"))
        assert json_report["summary"]["total_scanners"] == 0
        assert json_report["findings"] == []
        
        # SARIF
        sarif_report = json.loads(generator.generate(empty_results, format="sarif"))
        assert sarif_report["runs"][0]["results"] == []
    
    def test_all_passed_results(self, generator):
        """Test report generation when all scans pass."""
        passed_results = [
            ScanResult(
                scanner_name="manifest",
                passed=True,
                findings=[],
                metadata={"checks": 10}
            ),
            ScanResult(
                scanner_name="dependencies",
                passed=True,
                findings=[],
                metadata={"packages": 25}
            )
        ]
        
        md_report = generator.generate(passed_results, format="markdown")
        assert "✅ All scans passed!" in md_report
        assert "No security issues found" in md_report
    
    def test_invalid_format(self, generator, sample_results):
        """Test handling of invalid report format."""
        with pytest.raises(ValueError) as exc_info:
            generator.generate(sample_results, format="invalid")
        
        assert "format" in str(exc_info.value).lower()
    
    def test_severity_ordering(self, generator):
        """Test that findings are ordered by severity."""
        results = [
            ScanResult(
                scanner_name="test",
                passed=False,
                findings=[
                    Finding(
                        severity=FindingSeverity.INFO,
                        category=FindingCategory.INFORMATION,
                        title="Info finding",
                        description="Information"
                    ),
                    Finding(
                        severity=FindingSeverity.CRITICAL,
                        category=FindingCategory.VULNERABILITY,
                        title="Critical finding",
                        description="Critical issue"
                    ),
                    Finding(
                        severity=FindingSeverity.WARNING,
                        category=FindingCategory.CONFIGURATION,
                        title="Warning finding",
                        description="Warning"
                    )
                ]
            )
        ]
        
        json_report = json.loads(generator.generate(results, format="json"))
        findings = json_report["findings"]
        
        # Should be ordered: CRITICAL, WARNING, INFO
        assert findings[0]["severity"] == "critical"
        assert findings[1]["severity"] == "warning"
        assert findings[2]["severity"] == "info"
    
    def test_metadata_inclusion(self, generator, sample_results):
        """Test that scanner metadata is included in reports."""
        json_report = json.loads(generator.generate(sample_results, format="json"))
        
        # Check scanner metadata
        manifest_scanner = next(s for s in json_report["scanners"] if s["name"] == "manifest")
        assert manifest_scanner["metadata"]["manifest_path"] == "/test/mcp.json"
        assert manifest_scanner["metadata"]["server_name"] == "test-server"
        
        # Check report metadata
        assert "generated_at" in json_report["metadata"]
        assert "mcp_sec_version" in json_report["metadata"]
    
    def test_save_report(self, generator, sample_results, tmp_path):
        """Test saving reports to files."""
        # Test each format
        formats = ["markdown", "json", "sarif"]
        extensions = {"markdown": ".md", "json": ".json", "sarif": ".sarif.json"}
        
        for format in formats:
            output_file = tmp_path / f"report{extensions[format]}"
            
            generator.save_report(
                sample_results,
                output_file=str(output_file),
                format=format
            )
            
            assert output_file.exists()
            content = output_file.read_text()
            
            if format in ["json", "sarif"]:
                # Should be valid JSON
                json.loads(content)
            else:
                # Markdown should have content
                assert len(content) > 100
                assert "MCP Security Scan Report" in content