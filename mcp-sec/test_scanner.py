#!/usr/bin/env python3
"""Test script to demonstrate MCP Security Scanner."""

import json
from pathlib import Path
from mcp_sec.scanners import workspace_scanner, dependency_scanner
from mcp_sec.reporters import generate_report, ReportFormat

def test_workspace_scan():
    """Test workspace scanning for security issues."""
    print("Testing workspace scanner...")
    
    # Scan the example workspace
    result = workspace_scanner.scan(Path("examples/test-workspace"))
    
    print(f"\nFound {len(result.findings)} security issues")
    print(f"Total risk score: {result.total_risk_score:.2f}")
    
    # Generate markdown report
    report = generate_report(result, ReportFormat.MARKDOWN)
    print("\n--- WORKSPACE SCAN REPORT ---")
    print(report)

def test_dependency_scan():
    """Test dependency scanning."""
    print("\n\nTesting dependency scanner...")
    
    # Scan dependencies
    result = dependency_scanner.scan(Path("examples/test-workspace"))
    
    print(f"\nFound {len(result.findings)} dependency issues")
    print(f"Total risk score: {result.total_risk_score:.2f}")
    
    # Generate JSON report
    report = generate_report(result, ReportFormat.JSON)
    print("\n--- DEPENDENCY SCAN REPORT (JSON) ---")
    data = json.loads(report)
    print(json.dumps(data, indent=2))

def test_manifest_validation():
    """Test manifest validation."""
    print("\n\nTesting manifest validation...")
    
    # This would normally scan a real server URL
    # For demo purposes, we'll show what issues would be found
    print("Example issues in vulnerable-manifest.json:")
    print("- Typosquatting: 'fiIesystem' looks like 'filesystem'")
    print("- Semantic drift: Claims to be 'safe file reader' but has delete_after parameter")
    print("- Excessive permissions: filesystem:write, process:spawn, network:*")
    print("- Schema issues: Accepts any pattern (.*) and additionalProperties")

if __name__ == "__main__":
    print("MCP Security Scanner Demo\n")
    
    test_workspace_scan()
    test_dependency_scan()
    test_manifest_validation()
    
    print("\n\nDemo complete!")