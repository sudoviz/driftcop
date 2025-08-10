# MCP Security Scanner - Feature Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                          MCP SECURITY SCANNER - DRIFTCOP                            │
│                         "Shift-Left Security for MCP Servers"                       │
│                              Version 0.2.0 - Phase 1 Complete                       │
│                      Now with Auto-Discovery and Advanced Analyzers                 │
└─────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                            DISCOVERY & AUTO-DETECTION (NEW)                         │
├─────────────────────────────────────────────────────────────────────────────────────┤
│  ┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐    │
│  │  CLIENT DISCOVERY    │  │   CONFIG PARSER      │  │   SERVER FINDER      │    │
│  ├──────────────────────┤  ├──────────────────────┤  ├──────────────────────┤    │
│  │ • Claude configs     │─▶│ • Format detection   │─▶│ • Auto-discovery     │    │
│  │ • Cursor configs     │  │ • Multi-client       │  │ • Cross-client scan  │    │
│  │ • VSCode configs     │  │ • Unified parsing    │  │ • Config aggregation │    │
│  │ • Windsurf configs   │  │ • JSON/YAML support  │  │ • Security analysis  │    │
│  └──────────────────────┘  └──────────────────────┘  └──────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                                   CORE SCANNERS                                     │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐    │
│  │   SERVER SCANNER     │  │  WORKSPACE SCANNER   │  │  DEPENDENCY SCANNER  │    │
│  ├──────────────────────┤  ├──────────────────────┤  ├──────────────────────┤    │
│  │ ✅ Manifest validation│  │ • Prompt injection   │  │ • CVE detection      │    │
│  │ ✅ Schema checking    │  │ • MCP tool extraction│  │ • Typosquatting      │    │
│  │ ✅ Permission audit   │  │ • Code pattern match │  │ • Version checks     │    │
│  │ ✅ Typo detection     │  │ • Zero-width chars   │  │ • Package analysis   │    │
│  │ ✅ Semantic analysis  │  │ • Security patterns  │  │ • Lock verification  │    │
│  └──────────────────────┘  └──────────────────────┘  └──────────────────────┘    │
│           ▲                          ▲                          ▲                   │
│           │                          │                          │                   │
│           └──────────────────────────┴──────────────────────────┘                  │
│                                      │                                              │
└──────────────────────────────────────┴──────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                               SECURITY ANALYZERS                                    │
├─────────────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────┐      ┌─────────────────────────────────┐    │
│  │   ✅ TYPO DETECTOR (FIXED)      │      │ ✅ SEMANTIC ANALYZER (FIXED)   │    │
│  ├─────────────────────────────────┤      ├─────────────────────────────────┤    │
│  │  fiIesystem ≈ filesystem       │      │  🤖 OpenAI LLM Analysis         │    │
│  │  ┌───────────────────┐         │      │  ┌─────────────────────┐       │    │
│  │  │ Levenshtein ≤ 2   │         │      │  │ Description:        │       │    │
│  │  │ Dice coefficient  │ ◄───────┼──────┼─▶│ "Read-only tool"    │       │    │
│  │  │ Homograph check   │         │      │  │ Schema:             │       │    │
│  │  │ TF-IDF + Cosine   │         │      │  │ {delete: true} ❌   │       │    │
│  │  └───────────────────┘         │      │  └─────────────────────┘       │    │
│  └─────────────────────────────────┘      └─────────────────────────────────┘    │
│                                                                                     │
│  ┌─────────────────────────────────┐      ┌─────────────────────────────────┐    │
│  │   TOOL POISONING (NEW)          │      │    CROSS-ORIGIN (NEW)          │    │
│  ├─────────────────────────────────┤      ├─────────────────────────────────┤    │
│  │ • Command injection patterns    │      │ • Attack chain detection        │    │
│  │ • Data exfiltration detection   │      │ • Privilege escalation paths    │    │
│  │ • Destructive operations        │      │ • Cross-server data theft       │    │
│  │ • Obfuscation techniques        │      │ • Server collusion analysis     │    │
│  └─────────────────────────────────┘      └─────────────────────────────────┘    │
│                                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────────────┐  │
│  │                          TOXIC FLOW ANALYZER (NEW)                          │  │
│  ├─────────────────────────────────────────────────────────────────────────────┤  │
│  │  Download → Execute | Read → Upload | List → Delete | Dangerous Combos      │  │
│  └─────────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                            CRYPTOGRAPHIC SECURITY                                   │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌─────────────────────┐     ┌─────────────────────┐     ┌─────────────────────┐ │
│  │   TOOL HASHING      │     │  SIGSTORE SIGNING  │     │  VERSION TRACKING   │ │
│  ├─────────────────────┤     ├─────────────────────┤     ├─────────────────────┤ │
│  │                     │     │                     │     │                     │ │
│  │  Tool Definition    │     │  ┌──────────────┐  │     │  v1.0 ──► v1.1     │ │
│  │       ↓             │     │  │ DSSE Format  │  │     │    ↓       ↓       │ │
│  │  Canonical JSON     │     │  │ OIDC Auth    │  │     │  Hash₁ ≠ Hash₂     │ │
│  │       ↓             │     │  │ Transparency │  │     │    ↓       ↓       │ │
│  │  SHA-256 Hash       │     │  └──────────────┘  │     │  🔔 Notification   │ │
│  │       ↓             │     │         ↓           │     │    ↓       ↓       │ │
│  │  abc123def456...    │     │    ✓ Verified      │     │  ⚠️  Approval Req  │ │
│  │                     │     │                     │     │                     │ │
│  └─────────────────────┘     └─────────────────────┘     └─────────────────────┘ │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              CHANGE MANAGEMENT                                      │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│   ┌────────────┐     ┌────────────┐     ┌────────────┐     ┌────────────┐        │
│   │  DETECTION │ ──► │   NOTIFY   │ ──► │  APPROVAL  │ ──► │   APPLY    │        │
│   └────────────┘     └────────────┘     └────────────┘     └────────────┘        │
│         │                   │                   │                   │               │
│         ▼                   ▼                   ▼                   ▼               │
│   ╔════════════╗     ╔════════════╗     ╔════════════╗     ╔════════════╗        │
│   ║ Tool Added ║     ║ Risk Level ║     ║ ✓ Approve  ║     ║ Tool Active║        │
│   ║ Perm Change║     ║ Stored DB  ║     ║ ✗ Reject   ║     ║ Or Blocked ║        │
│   ║ Hash Change║     ║ SQLite     ║     ║ CLI/API    ║     ║ Tracked    ║        │
│   ╚════════════╝     ╚════════════╝     ╚════════════╝     ╚════════════╝        │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                               REPORTING ENGINE                                      │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│   ┌─────────────┐        ┌─────────────┐        ┌─────────────┐                  │
│   │  MARKDOWN   │        │    JSON     │        │    SARIF    │                  │
│   ├─────────────┤        ├─────────────┤        ├─────────────┤                  │
│   │ # Report    │        │ {           │        │ GitHub      │                  │
│   │ - Finding 1 │        │  "findings":│        │ Security    │                  │
│   │ - Finding 2 │        │   [...]     │        │ Tab Ready   │                  │
│   │ Risk: 7.5   │        │ }           │        │ CI/CD       │                  │
│   └─────────────┘        └─────────────┘        └─────────────┘                  │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              SECURITY FINDINGS                                      │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  CRITICAL ████████████████████████████████████████████████████ (10.0)            │
│  HIGH     ████████████████████████████████████                 (7.0)             │
│  MEDIUM   ████████████████████                                 (4.0)             │
│  LOW      ████                                                 (1.0)             │
│  INFO     ·                                                    (0.0)             │
│                                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────────┐     │
│  │ FINDING TYPES:                                                           │     │
│  ├─────────────────────────────────────────────────────────────────────────┤     │
│  │                                                                           │     │
│  │ 🎭 TYPOSQUATTING        Lookalike server names (fiIesystem ≈ filesystem)│     │
│  │ 🔀 SEMANTIC_DRIFT       Description doesn't match capabilities          │     │
│  │ 🚨 DEPENDENCY_VULN      Known CVEs or supply chain risks               │     │
│  │ 💉 PROMPT_INJECTION     Hidden instructions or malicious patterns       │     │
│  │ 🔓 EXCESSIVE_PERMS      Dangerous permissions (write, spawn, network)   │     │
│  │ 📝 SCHEMA_VIOLATION     Invalid manifest structure or content           │     │
│  │ 🔏 SIGNATURE_INVALID    Missing or invalid cryptographic signature      │     │
│  │ 📊 VERSION_CHANGE       Tool definition has changed since last scan     │     │
│  │                                                                           │     │
│  └─────────────────────────────────────────────────────────────────────────┤     │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                                CLI COMMANDS                                         │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  $ driftcop scan-server https://example.com/mcp-server                             │
│  $ driftcop scan-workspace /path/to/project                                        │
│  $ driftcop scan-deps /path/to/project                                            │
│  $ driftcop risk-report scan-results.json --format sarif                          │
│  $ driftcop ci-hook https://example.com --threshold 5.0                           │
│  $ driftcop check-changes                    # View pending approvals              │
│  $ driftcop check-changes --approve abc123   # Approve a change                    │
│  $ driftcop verify-signature manifest.json   # Verify digital signature            │
│  $ driftcop show-hash manifest.json          # Calculate tool hashes               │
│  $ driftcop lock add manifest.json --sign    # Add to lock file with signature     │
│  $ driftcop lock verify manifest.json        # Verify against lock file            │
│  $ driftcop sign manifest.json               # Sign with Sigstore                  │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              DATA FLOW                                              │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│   MCP Server URL                                                                    │
│        │                                                                            │
│        ▼                                                                            │
│   ┌─────────┐     ┌──────────┐     ┌───────────┐     ┌──────────┐                │
│   │ FETCH   │ ──► │ VALIDATE │ ──► │  ANALYZE  │ ──► │  REPORT  │                │
│   │ Manifest│     │  Schema  │     │  Security │     │ Findings │                │
│   └─────────┘     └──────────┘     └───────────┘     └──────────┘                │
│        │               │                   │                │                       │
│        ▼               ▼                   ▼                ▼                       │
│   ╔═════════╗    ╔═══════════╗      ╔═══════════╗    ╔══════════╗                │
│   ║ HTTP(S) ║    ║ JSONSchema║      ║ • Typo    ║    ║ MD/JSON/ ║                │
│   ║ Request ║    ║ Validator ║      ║ • Semantic║    ║  SARIF   ║                │
│   ║ + Parse ║    ║ + Rules   ║      ║ • Crypto  ║    ║ + Exit   ║                │
│   ╚═════════╝    ╚═══════════╝      ╚═══════════╝    ╚══════════╝                │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

## Feature Matrix

```
┌──────────────────────┬────────────┬────────────┬─────────────┬────────────────┐
│      Feature         │   Status   │ Complexity │   Security  │  User Impact   │
├──────────────────────┼────────────┼────────────┼─────────────┼────────────────┤
│ Manifest Validation  │     ✅     │    Low     │   Critical  │     High       │
│ Typosquatting Check  │     ✅     │   Medium   │     High    │    Medium      │
│ Semantic Analysis    │     ✅     │    High    │   Medium    │     High       │
│ Dependency Scan      │     ✅     │   Medium   │     High    │    Medium      │
│ Workspace Scan       │     ✅     │   Medium   │   Medium    │     High       │
│ Sigstore Signing     │     ✅     │    High    │   Critical  │    Medium      │
│ Version Tracking     │     ✅     │   Medium   │     High    │     High       │
│ Approval Workflow    │     ✅     │   Medium   │   Critical  │     High       │
│ SARIF Integration    │     ✅     │    Low     │     Low     │     High       │
│ Language Extractors  │     ✅     │    High    │     High    │     High       │
│ Lock File Manager    │     ✅     │   Medium   │     High    │     High       │
│ Multiple Reporters   │     ✅     │    Low     │     Low     │     High       │
│ Docker Sandbox       │     ❌     │    High    │   Critical  │     Low        │
│ Network Analysis     │     ❌     │    High    │     High    │    Medium      │
│ Runtime Monitoring   │     ❌     │   V.High   │   Critical  │     High       │
└──────────────────────┴────────────┴────────────┴─────────────┴────────────────┘

Legend: ✅ Complete  ⏳ In Progress  ❌ Not Started
```

## Language Extractor Support

```
┌──────────────────────┬────────────┬──────────────────────────────────────────┐
│     Language         │   Status   │              Capabilities                │
├──────────────────────┼────────────┼──────────────────────────────────────────┤
│ Python               │     ✅     │ Tool definitions, MCP client usage       │
│ JavaScript/TypeScript│     ✅     │ Tool definitions, MCP client usage       │
│ Go                   │     ✅     │ Tool definitions, MCP client usage       │
│ Rust                 │     ✅     │ Tool definitions, MCP client usage       │
│ Java                 │     ✅     │ Tool definitions, MCP client usage       │
│ C#                   │     ✅     │ Tool definitions, MCP client usage       │
│ Ruby                 │     ✅     │ Tool definitions, MCP client usage       │
│ PHP                  │     ✅     │ Tool definitions, MCP client usage       │
│ JSON                 │     ✅     │ Static tool definitions                  │
│ YAML                 │     ✅     │ Static tool definitions                  │
└──────────────────────┴────────────┴──────────────────────────────────────────┘
```

## Key Implementation Details

### Security Scanners
- **Server Scanner**: Validates MCP manifests against JSON schema, performs typosquatting detection, semantic drift analysis, and tracks version changes
- **Workspace Scanner**: Detects prompt injection patterns, zero-width characters, and extracts MCP tool definitions from source code
- **Dependency Scanner**: Checks for known CVEs, typosquatted packages, and validates dependency lock files

### Cryptographic Features
- **Hashing**: SHA-256 based tool and manifest hashing with canonical JSON representation
- **Signing**: Sigstore integration with DSSE envelope format for supply chain security
- **Verification**: Support for signature verification and lock file integrity checks

### Change Management
- **Version Tracking**: SQLite-based tracking of manifest and tool changes over time
- **Approval Workflow**: Risk-based approval system for permission and tool changes
- **Notifications**: Automatic detection and notification of security-relevant changes

### Analysis Capabilities
- **Typosquatting Detection**: Levenshtein distance, Dice coefficient, and TF-IDF cosine similarity
- **Semantic Analysis**: OpenAI LLM integration for detecting mismatches between tool descriptions and capabilities
- **Pattern Matching**: Regex-based detection of security anti-patterns in code

### Output Formats
- **Markdown**: Human-readable reports with risk scores and remediation guidance
- **JSON**: Machine-readable format for integration with other tools
- **SARIF**: GitHub Security tab compatible format for CI/CD integration

### Configuration
- Configurable risk thresholds and known server lists
- SQLite databases for tracking and approval management
- TOML-based lock file format for manifest pinning