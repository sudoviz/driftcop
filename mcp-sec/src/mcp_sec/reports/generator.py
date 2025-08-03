"""Report generation for scan results."""

import json
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path

from mcp_sec.models import ScanResult, Finding, FindingSeverity


class ReportGenerator:
    """Generate reports in various formats."""
    
    def generate(self, results: List[ScanResult], format: str = "markdown") -> str:
        """Generate a report from scan results.
        
        Args:
            results: List of scan results
            format: Output format (markdown, json, sarif)
            
        Returns:
            Formatted report string
        """
        if format == "markdown":
            return self._generate_markdown(results)
        elif format == "json":
            return self._generate_json(results)
        elif format == "sarif":
            return self._generate_sarif(results)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def save_report(self, results: List[ScanResult], output_file: str, format: str = "markdown"):
        """Save report to a file."""
        report = self.generate(results, format)
        Path(output_file).write_text(report)
    
    def _generate_markdown(self, results: List[ScanResult]) -> str:
        """Generate Markdown format report."""
        lines = []
        lines.append("# MCP Security Scan Report")
        lines.append("")
        lines.append(f"Generated at: {datetime.now().isoformat()}")
        lines.append("")
        
        if not results:
            lines.append("No scanners were run.")
            return "\n".join(lines)
        
        # Summary
        lines.append("## Summary")
        lines.append("")
        
        total_scanners = len(results)
        passed = sum(1 for r in results if r.passed)
        failed = total_scanners - passed
        
        lines.append(f"- Total Scanners: {total_scanners}")
        lines.append(f"- Passed: {passed}")
        lines.append(f"- Failed: {failed}")
        lines.append("")
        
        # Findings by severity
        all_findings = []
        for result in results:
            all_findings.extend(result.findings)
        
        if all_findings:
            severity_counts = self._count_by_severity(all_findings)
            lines.append("## Findings by Severity")
            lines.append("")
            for severity in FindingSeverity:
                count = severity_counts.get(severity.value, 0)
                if count > 0:
                    emoji = self._get_severity_emoji(severity)
                    lines.append(f"- {emoji} {severity.value.title()}: {count}")
            lines.append("")
            
            # Detailed findings
            lines.append("## Detailed Findings")
            lines.append("")
            
            # Sort by severity
            sorted_findings = sorted(all_findings, key=lambda f: self._severity_order(f.severity))
            
            for i, finding in enumerate(sorted_findings, 1):
                emoji = self._get_severity_emoji(finding.severity)
                lines.append(f"### {i}. {emoji} {finding.title}")
                lines.append("")
                lines.append(f"**Severity:** {finding.severity.value}")
                lines.append(f"**Category:** {finding.category.value}")
                lines.append(f"**Description:** {finding.description}")
                
                if finding.recommendation:
                    lines.append(f"**Recommendation:** {finding.recommendation}")
                
                if finding.file_path:
                    lines.append(f"**File:** {finding.file_path}")
                    if finding.line_number:
                        lines.append(f"**Line:** {finding.line_number}")
                
                lines.append("")
        else:
            lines.append("✅ All scans passed!")
            lines.append("")
            lines.append("No security issues found.")
        
        # Scanner details
        lines.append("")
        lines.append("## Scanner Results")
        lines.append("")
        
        for result in results:
            status = "✅ PASSED" if result.passed else "❌ FAILED"
            lines.append(f"### {result.scanner_name} - {status}")
            lines.append("")
            
            if result.metadata:
                lines.append("**Metadata:**")
                for key, value in result.metadata.items():
                    if key != "extracted_tools":  # Skip large data
                        lines.append(f"- {key}: {value}")
                lines.append("")
        
        return "\n".join(lines)
    
    def _generate_json(self, results: List[ScanResult]) -> str:
        """Generate JSON format report."""
        all_findings = []
        for result in results:
            for finding in result.findings:
                all_findings.append({
                    "scanner": result.scanner_name,
                    "severity": finding.severity.value,
                    "category": finding.category.value,
                    "title": finding.title,
                    "description": finding.description,
                    "recommendation": finding.recommendation,
                    "file_path": finding.file_path,
                    "line_number": finding.line_number,
                    "metadata": finding.metadata
                })
        
        # Sort by severity
        all_findings.sort(key=lambda f: self._severity_order(FindingSeverity(f["severity"])))
        
        report = {
            "summary": {
                "total_scanners": len(results),
                "passed": sum(1 for r in results if r.passed),
                "failed": sum(1 for r in results if not r.passed),
                "total_findings": len(all_findings),
                "findings_by_severity": self._count_by_severity([
                    Finding(
                        severity=FindingSeverity(f["severity"]),
                        category=f["category"],
                        title=f["title"],
                        description=f["description"]
                    ) for f in all_findings
                ])
            },
            "scanners": [
                {
                    "name": r.scanner_name,
                    "passed": r.passed,
                    "findings_count": len(r.findings),
                    "metadata": r.metadata
                } for r in results
            ],
            "findings": all_findings,
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "mcp_sec_version": "0.1.0"
            }
        }
        
        return json.dumps(report, indent=2)
    
    def _generate_sarif(self, results: List[ScanResult]) -> str:
        """Generate SARIF format report."""
        rules = {}
        results_list = []
        
        for scan_result in results:
            for finding in scan_result.findings:
                # Create rule ID
                rule_id = f"{finding.category.value}_{finding.severity.value}"
                
                # Add rule if not exists
                if rule_id not in rules:
                    rules[rule_id] = {
                        "id": rule_id,
                        "name": finding.category.value,
                        "shortDescription": {
                            "text": f"{finding.category.value} - {finding.severity.value}"
                        },
                        "defaultConfiguration": {
                            "level": self._sarif_level(finding.severity)
                        }
                    }
                
                # Create result
                result = {
                    "ruleId": rule_id,
                    "level": self._sarif_level(finding.severity),
                    "message": {
                        "text": finding.description
                    },
                    "locations": []
                }
                
                # Add location if available
                if finding.file_path:
                    location = {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.file_path
                            }
                        }
                    }
                    
                    if finding.line_number:
                        location["physicalLocation"]["region"] = {
                            "startLine": finding.line_number
                        }
                    
                    result["locations"].append(location)
                else:
                    # Add empty location for consistency
                    result["locations"] = []
                
                results_list.append(result)
        
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "mcp-sec",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/mcp-security/mcp-sec",
                            "rules": list(rules.values())
                        }
                    },
                    "results": results_list
                }
            ]
        }
        
        return json.dumps(sarif, indent=2)
    
    def _count_by_severity(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {}
        for finding in findings:
            severity = finding.severity.value
            counts[severity] = counts.get(severity, 0) + 1
        return counts
    
    def _severity_order(self, severity: FindingSeverity) -> int:
        """Get numeric order for severity (higher = more severe)."""
        order = {
            FindingSeverity.CRITICAL: 6,
            FindingSeverity.HIGH: 5,
            FindingSeverity.MEDIUM: 4,
            FindingSeverity.WARNING: 3,
            FindingSeverity.LOW: 2,
            FindingSeverity.INFO: 1,
            FindingSeverity.ERROR: 5  # Treat errors as high severity
        }
        return -order.get(severity, 0)  # Negative for descending sort
    
    def _get_severity_emoji(self, severity: FindingSeverity) -> str:
        """Get emoji for severity level."""
        emojis = {
            FindingSeverity.CRITICAL: "🔴",
            FindingSeverity.HIGH: "🟠",
            FindingSeverity.MEDIUM: "🟡",
            FindingSeverity.WARNING: "🟡",
            FindingSeverity.LOW: "🔵",
            FindingSeverity.INFO: "ℹ️",
            FindingSeverity.ERROR: "❌"
        }
        return emojis.get(severity, "•")
    
    def _sarif_level(self, severity: FindingSeverity) -> str:
        """Convert severity to SARIF level."""
        mapping = {
            FindingSeverity.CRITICAL: "error",
            FindingSeverity.HIGH: "error",
            FindingSeverity.MEDIUM: "warning",
            FindingSeverity.WARNING: "warning",
            FindingSeverity.LOW: "note",
            FindingSeverity.INFO: "note",
            FindingSeverity.ERROR: "error"
        }
        return mapping.get(severity, "warning")