#!/usr/bin/env python3
"""
Simple command-line testing script for MCP Security Scanner
Usage: python3 test_simple.py [command] [args...]

Commands:
  hash <text>                    - Compute hash of text
  validate <manifest.json>       - Validate MCP manifest  
  scan-patterns <file>           - Scan file for security patterns
  check-typo <name>              - Check for typosquatting
  create-finding                 - Create a sample finding
  test-all                       - Run all basic tests
"""

import sys
import json
import re
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def cmd_hash(text):
    """Compute hash of text."""
    from mcp_sec.crypto.hash import compute_digest
    
    digest = compute_digest(text)
    print(f"Text: {text}")
    print(f"Hash: {digest}")
    return digest

def cmd_validate(manifest_path):
    """Validate MCP manifest file."""
    from jsonschema import validate, ValidationError
    
    # Basic MCP schema
    schema = {
        "type": "object",
        "required": ["name", "version", "description"],
        "properties": {
            "name": {"type": "string"},
            "version": {"type": "string", "pattern": r"^\d+\.\d+\.\d+"},
            "description": {"type": "string"},
            "tools": {"type": "array"},
            "permissions": {"type": "array"}
        }
    }
    
    try:
        with open(manifest_path) as f:
            manifest = json.load(f)
        
        validate(manifest, schema)
        print(f"✓ {manifest_path} is valid")
        print(f"  Name: {manifest.get('name')}")
        print(f"  Version: {manifest.get('version')}")
        print(f"  Tools: {len(manifest.get('tools', []))}")
        return True
        
    except ValidationError as e:
        print(f"✗ Validation error: {e.message}")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def cmd_scan_patterns(file_path):
    """Scan file for security patterns."""
    patterns = [
        (r'<!--.*?-->', "HTML comments"),
        (r'(system|assistant):\s*(ignore|forget|disregard)', "System prompt manipulation"),
        (r'<script', "Script injection"),
        (r'mcp\.invoke.*filesystem:write', "Filesystem write access"),
        (r'{{.*?}}|{%.*?%}', "Template injection"),
        (r'password\s*=\s*["\'][^"\']+["\']', "Hardcoded password")
    ]
    
    try:
        with open(file_path) as f:
            content = f.read()
        
        print(f"Scanning {file_path} for security patterns...")
        
        findings = []
        for pattern, description in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                findings.append((line_num, description, match.group()))
        
        if findings:
            print(f"Found {len(findings)} potential issues:")
            for line_num, desc, match_text in findings:
                print(f"  Line {line_num}: {desc}")
                print(f"    Match: {match_text[:50]}...")
        else:
            print("No security patterns detected")
        
        return len(findings) == 0
        
    except Exception as e:
        print(f"✗ Error scanning file: {e}")
        return False

def cmd_check_typo(name):
    """Check for typosquatting."""
    legitimate_names = [
        "filesystem", "github", "postgres", "sqlite", "slack", 
        "google-drive", "memory", "puppeteer", "brave-search"
    ]
    
    print(f"Checking '{name}' for typosquatting...")
    
    suspicious = []
    for legit in legitimate_names:
        # Simple edit distance
        distance = sum(c1 != c2 for c1, c2 in zip(name.ljust(len(legit)), legit.ljust(len(name))))
        
        if 0 < distance <= 2:
            suspicious.append((legit, distance))
    
    if suspicious:
        print(f"⚠️ Potential typosquatting detected:")
        for legit, dist in suspicious:
            print(f"  Similar to '{legit}' (edit distance: {dist})")
        return False
    else:
        print("✓ No typosquatting detected")
        return True

def cmd_create_finding():
    """Create a sample security finding."""
    from mcp_sec.models import Finding, FindingCategory, FindingSeverity
    
    finding = Finding(
        severity=FindingSeverity.HIGH,
        category=FindingCategory.TYPOSQUATTING,
        title="Sample Security Finding",
        description="This is a demonstration of creating a security finding",
        recommendation="Review and fix the identified issue",
        file_path="/example/path/file.py",
        line_number=42
    )
    
    print("Created sample finding:")
    print(f"  Title: {finding.title}")
    print(f"  Severity: {finding.severity}")
    print(f"  Category: {finding.category}")
    print(f"  File: {finding.file_path}:{finding.line_number}")
    print(f"  Description: {finding.description}")
    
    return finding

def cmd_test_all():
    """Run all basic tests."""
    print("Running all basic tests...\n")
    
    tests = [
        ("Hash computation", lambda: cmd_hash("test string")),
        ("Typo checking", lambda: cmd_check_typo("filesysem")),
        ("Finding creation", lambda: cmd_create_finding()),
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        try:
            result = test_func()
            results.append(True)
            print("✓ Test completed")
        except Exception as e:
            print(f"✗ Test failed: {e}")
            results.append(False)
    
    passed = sum(results)
    total = len(results)
    print(f"\n=== Summary ===")
    print(f"Tests passed: {passed}/{total}")
    
    return passed == total

def main():
    """Main command dispatcher."""
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    
    command = sys.argv[1]
    args = sys.argv[2:]
    
    try:
        if command == "hash":
            if not args:
                print("Usage: hash <text>")
                return 1
            cmd_hash(" ".join(args))
            
        elif command == "validate":
            if not args:
                print("Usage: validate <manifest.json>")
                return 1
            result = cmd_validate(args[0])
            return 0 if result else 1
            
        elif command == "scan-patterns":
            if not args:
                print("Usage: scan-patterns <file>")
                return 1
            result = cmd_scan_patterns(args[0])
            return 0 if result else 1
            
        elif command == "check-typo":
            if not args:
                print("Usage: check-typo <name>")
                return 1
            result = cmd_check_typo(args[0])
            return 0 if result else 1
            
        elif command == "create-finding":
            cmd_create_finding()
            
        elif command == "test-all":
            result = cmd_test_all()
            return 0 if result else 1
            
        else:
            print(f"Unknown command: {command}")
            print(__doc__)
            return 1
            
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())