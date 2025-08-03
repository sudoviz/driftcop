#!/usr/bin/env python3
"""
Example CI verification script using MCP Security lock files.

This demonstrates how to integrate lock file verification into CI/CD pipelines.
"""

import sys
import json
from pathlib import Path

# In a real CI environment, you'd import from the installed package
# from mcp_sec.lockfile import verify_workspace, verify_ci_digests


def verify_manifests_in_ci():
    """Example CI verification workflow."""
    
    # Option 1: Full lock file verification
    print("=== Full Lock File Verification ===")
    
    # Check if lock file exists
    lockfile = Path(".mcpsec-lock.toml")
    if not lockfile.exists():
        print("ERROR: No lock file found. Run 'driftcop lock add' first.")
        return False
    
    # Verify all manifests match lock file
    # In real usage:
    # results = verify_workspace(Path("."), lockfile)
    
    # For demo, we'll simulate the results
    results = {
        "summary": {
            "total": 2,
            "verified": 1,
            "failed": 1,
            "not_locked": 0,
            "errors": 0
        },
        "verified": [
            {"path": "examples/signed-manifest.json", "digest": "WGh2Y2g4MjBi..."}
        ],
        "failed": [
            {
                "path": "examples/vulnerable-manifest.json",
                "changes": {
                    "status": "modified",
                    "old_digest": "QmVhY2g3MjBi...",
                    "new_digest": "YmFzZTY0bmV3...",
                    "tool_changes": [
                        {"type": "modified", "name": "read_file"}
                    ]
                }
            }
        ]
    }
    
    print(f"Total manifests: {results['summary']['total']}")
    print(f"Verified: {results['summary']['verified']}")
    print(f"Failed: {results['summary']['failed']}")
    
    if results['summary']['failed'] > 0:
        print("\nFailed verifications:")
        for failure in results['failed']:
            print(f"  - {failure['path']}")
            if 'changes' in failure:
                for change in failure['changes'].get('tool_changes', []):
                    print(f"    Tool {change['type']}: {change['name']}")
    
    # Option 2: Lightweight digest verification
    print("\n=== Digest-Only Verification ===")
    
    # In CI, you might store just the digests
    expected_digests = {
        "examples/signed-manifest.json": "WGh2Y2g4MjBiZTk4ZjI3MzQ1Njc4OTBhYmNkZWY",
        "examples/vulnerable-manifest.json": "QmVhY2g3MjBiZTk4ZjI3MzQ1Njc4OTBhYmNkZWY"
    }
    
    # Verify digests
    # In real usage:
    # success, failures = verify_ci_digests(expected_digests, Path("."))
    
    # Return appropriate exit code
    return results['summary']['failed'] == 0


def generate_sbom_with_digests():
    """Generate Software Bill of Materials with MCP tool digests."""
    
    print("\n=== SBOM Generation ===")
    
    # Read lock file to get all tool digests
    # This would be integrated with your SBOM generation tool
    
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {
                "type": "library",
                "name": "mcp-tool-read-file",
                "version": "1.0.0",
                "hashes": [
                    {
                        "alg": "SHA-256",
                        "content": "YWJjZGVmMTIzNDU2Nzg5MA"
                    }
                ],
                "properties": [
                    {
                        "name": "mcp:tool-type",
                        "value": "filesystem:read"
                    }
                ]
            }
        ]
    }
    
    print(json.dumps(sbom, indent=2))


def main():
    """Main CI verification entry point."""
    
    print("MCP Security CI Verification")
    print("=" * 40)
    
    # Run verification
    success = verify_manifests_in_ci()
    
    # Generate SBOM if requested
    if "--sbom" in sys.argv:
        generate_sbom_with_digests()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()