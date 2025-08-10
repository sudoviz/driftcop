# MCP Security Scanner (mcp-sec)

A security scanner for Model Context Protocol (MCP) servers that helps developers identify and fix security issues before running MCP agents.

## Features

### Core Security Scanning
- **Manifest Scanning**: Validates MCP server manifests against schema and security best practices
- **Typosquatting Detection**: Uses Levenshtein distance and character embeddings to detect potential typosquatting attacks
- **Semantic Drift Analysis**: LLM-powered detection of mismatches between tool descriptions and actual capabilities
- **Dependency Scanning**: Identifies vulnerable dependencies and typosquatted packages
- **Workspace Scanning**: Detects prompt injection patterns and hardcoded credentials in code

### Advanced Threat Detection (New)
- **Auto-Discovery**: Automatically finds all MCP configurations across Claude, Cursor, VSCode, and Windsurf
- **Tool Poisoning Detection**: Identifies malicious patterns in tool descriptions (command injection, data exfiltration)
- **Cross-Origin Attack Detection**: Detects attack chains across multiple MCP servers
- **Toxic Flow Analysis**: Identifies dangerous tool combinations (download→execute, read→upload)
- **Multi-Client Support**: Scans configurations from all major MCP clients simultaneously

### Security Infrastructure
- **Multiple Report Formats**: Markdown, JSON, and SARIF for CI/CD integration
- **Immutable Tool Hashing**: Generate cryptographic fingerprints of tool definitions
- **Digital Signature Verification**: Verify manifest authenticity with RSA/Ed25519 signatures
- **Version Tracking**: Detect changes in tool definitions across scans
- **Change Approval Workflow**: Require explicit approval for significant changes
- **Language Extractor**: Extract MCP tool definitions from source code in 10+ languages using Tree-sitter

## Installation

```bash
pip install driftcop
```

Or using Poetry:

```bash
poetry install
```

## Usage

### Discover All MCP Configurations (New)

```bash
# Discover all MCP configurations on your system
driftcop discover

# Discover and scan for security issues
driftcop discover --scan

# Discover configurations for a specific client
driftcop discover --client cursor --scan
```

### Comprehensive Security Scan (New)

```bash
# Scan all discovered MCP configurations
driftcop scan-all

# Generate a comprehensive report
driftcop scan-all --output full-report.json --format json
```

### Traditional Scanning

```bash
# Scan a specific MCP server
driftcop scan-server https://example.com/mcp-server

# Scan a workspace
driftcop scan-workspace /path/to/project

# Scan dependencies
driftcop scan-deps /path/to/project
```

### Generate Reports

```bash
# Markdown report (default)
driftcop scan-server https://example.com/mcp-server -o report.md

# JSON report
driftcop scan-server https://example.com/mcp-server -o report.json -f json

# SARIF report for CI/CD
driftcop scan-server https://example.com/mcp-server -o report.sarif -f sarif
```

### CI/CD Integration

```bash
# Exit with non-zero code if risk exceeds threshold
driftcop ci-hook https://example.com/mcp-server --threshold 5.0 --sarif report.sarif
```

### Version Tracking and Change Management

```bash
# Check for pending changes requiring approval
driftcop check-changes

# Approve a specific change
driftcop check-changes --approve <change-id>

# Reject a change with reason
driftcop check-changes --reject <change-id> --reason "Excessive permissions"
```

### Cryptographic Features

```bash
# Calculate and display manifest hash
driftcop show-hash manifest.json

# Verify a digitally signed manifest
driftcop verify-signature signed-manifest.json

# Verify with external public key
driftcop verify-signature manifest.json --key public-key.pem
```

## Configuration

Set environment variables to configure the scanner:

- `OPENAI_API_KEY`: API key for LLM-based semantic analysis
- `MCP_SEC_MAX_RISK_SCORE`: Maximum acceptable risk score (default: 7.0)
- `MCP_SEC_TYPO_SIMILARITY_THRESHOLD`: Similarity threshold for typosquatting (default: 0.92)

## Security Checks

### Typosquatting Detection
- Levenshtein distance ≤ 2 from known MCP servers
- Dice coefficient similarity check
- Homograph attack detection (similar-looking characters)
- Character-level embedding similarity

### Semantic Drift Detection
- Analyzes if tool descriptions match their schemas
- Detects tools that claim to be read-only but have write parameters
- Identifies overly broad or suspicious permissions

### Dependency Security
- Checks for known CVEs in dependencies
- Detects unpinned versions and git dependencies
- Identifies typosquatted package names

### Prompt Injection Detection
- Hidden markdown/HTML comments
- Zero-width characters
- System prompt manipulation attempts
- Template injection patterns

### Cryptographic Verification
- **Tool Hashing**: Each tool gets a SHA-256 hash of its canonical JSON representation
- **Manifest Fingerprinting**: Complete manifest hash includes all tool hashes
- **Digital Signatures**: Support for RSA-SHA256 and Ed25519 signatures
- **Certificate Validation**: Verify signer identity through X.509 certificates

### Version Tracking
- **Change Detection**: Automatically detects when tool definitions change
- **Approval Workflow**: Significant changes require explicit approval
- **Audit Trail**: All changes are logged with timestamps and hashes
- **Notification System**: Get alerts when MCP servers change their capabilities

### Language Extractor
- **Tree-sitter Parsing**: Robust AST-based extraction from source code
- **Multi-Language Support**: Python, JavaScript, TypeScript, Go, Rust, Java, C#, Ruby, PHP, C++
- **Pattern Detection**: Recognizes decorators, annotations, class definitions, and object literals
- **Schema Extraction**: Captures input/output schemas from code
- **Line-Level Tracking**: Reports exact file location of tool definitions

## Risk Scoring

Findings are categorized by severity:
- **Critical** (10.0): Immediate security risk
- **High** (7.0): Serious security concern
- **Medium** (4.0): Moderate risk
- **Low** (1.0): Minor issue
- **Info** (0.0): Informational

## Development

```bash
# Install development dependencies
poetry install

# Run tests
poetry run pytest

# Format code
poetry run black src tests
poetry run ruff src tests

# Type checking
poetry run mypy src
```

## License

MIT