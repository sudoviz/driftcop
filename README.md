<!-- README.md – Drift-Cop ⚔️👁‍🗨 -->
<p align="center">
  <strong>DriftCop.</strong><br/>
  The <em>ultrafast-fast</em> security cop keeping your MCP servers locked-in and locked-down.
</p>

<p align="center">
  <a href="https://github.com/your-org/drift-cop/actions"><img src="https://img.shields.io/github/actions/workflow/status/your-org/drift-cop/ci.yml?style=for-the-badge&label=CI%20&%20Tests" alt="CI Status"></a>
  <a href="https://www.npmjs.com/package/drift-cop"><img src="https://img.shields.io/npm/v/drift-cop?style=for-the-badge" alt="npm version"></a>
  <a href="https://github.com/your-org/drift-cop/blob/main/LICENSE"><img src="https://img.shields.io/github/license/your-org/drift-cop?style=for-the-badge" alt="License"></a>
  <a href="https://twitter.com/intent/tweet?text=Meet%20Drift-Cop%20%E2%80%94%20the%20MCP%20drift-busting%20security%20bot!&url=https://github.com/your-org/drift-cop"><img src="https://img.shields.io/badge/Tweet-Spread%20the%20Word-1DA1F2?style=for-the-badge&logo=twitter" alt="Tweet"></a>
</p>

---
## 🎯 What is DriftCop?

Drift-Cop is your Enterprise grade MCP security scanner based CLI + live dashboard that spots dangerous drift in AI tools. It spots injection hacks, and CVEs, signs every change in SigStore. Drift-Cop is designed to help AI developers and InfoSec organizations identify, track, and mitigate security vulnerabilities in MCP server implementations they use from external untrusted sources. 

## 🔥 Why Drift-Cop?

1. **Spot the Drift _instantly_** – Diff every manifest, dependency and workspace change against golden baselines in real-time.  
2. **Attack-aware Scanning** – Rug-pull, typosquat, supply-chain & prompt-injection rules baked-in and update daily.  
3. **Actionable Autopilot** – AI-generated fixes, PR suggestions and Slack/SIEM alerts 🚨.  
4. **Two-Piece Powerhouse** – Lightweight CLI + Cloud Control-Plane give you end-to-end coverage without vendor lock-in.  

> “We caught an auth-bypass typo _before_ it hit production. Drift-Cop paid for itself on day one.” – _A Very Happy DevOps Lead_

---

Drift-Cop is a defensive security platform designed to help developers and organizations identify, track, and mitigate security vulnerabilities in MCP server implementations. It consists of two main components working seamlessly together to provide end-to-end security coverage.

## 📸 Dashboard Preview

<div align="center">
  <img src="logos/driftcopdashboard.gif" alt="Drift Cop Dashboard in Action" width="800">
</div>

## 🎥 Demo Video

<div align="center">
  <iframe width="800" height="450" src="https://www.youtube.com/embed/ZJ-OocWpu44?si=Va2HfpNcA5Ba9Lbf" title="Drift-Cop Demo Video" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>
  <p><em>Watch the Drift-Cop demo video above</em></p>
  <p><em>Real-time drift monitoring and approval workflow</em></p>
</div>

## 📦 Components

### 1. MCP Security Scanner (mcp-sec)
A powerful command-line security scanner that performs deep analysis of MCP servers, codebases, and dependencies.

**Key Features:**
- **Multi-Layer Scanning**: Comprehensive analysis of server manifests, workspace code, and dependencies
- **Advanced Threat Detection**: 
  - Typosquatting detection using Levenshtein distance and TF-IDF similarity
  - Semantic drift analysis powered by LLM to detect mismatches between descriptions and capabilities
  - Prompt injection pattern detection including hidden characters and system manipulation
  - Known CVE scanning in dependencies
- **Cryptographic Security**:
  - SHA-256 based tool hashing with canonical JSON representation
  - Sigstore integration for digital signatures (DSSE envelope format)
  - Version tracking to detect unauthorized changes
  - Lock file management for manifest pinning
- **Language Support**: Extracts MCP tool definitions from 10+ languages using Tree-sitter AST parsing
- **Flexible Reporting**: Markdown, JSON, and SARIF formats for CI/CD integration

### 2. MCP Security Web UI (mcp-sec-web)
A modern React-based dashboard providing real-time visualization and management of security findings.

**Key Features:**
- **Real-Time Dashboard**: Live monitoring of configuration drifts and security issues
- **Interactive Approval Workflows**: 
  - Quick approve for low-risk changes
  - Detailed review process for high-risk modifications
  - Complete audit trail with timestamps and approver tracking
- **Advanced Filtering & Search**: Filter by severity, environment, repository, or custom search
- **Bulk Operations**: Select and approve multiple drifts simultaneously
- **Data Export**: CSV and JSON export for reporting and analysis
- **Zero-Integration Design**: Works with existing MCP-SEC installations without code modifications
```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              MCP SECURITY SCANNER (mcp-sec/)                         │
│                         "Shift-Left Security for MCP Servers"                       │
│                                   Version 0.1.0                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                                   CORE SCANNERS                                     │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐       │
│  │   SERVER SCANNER     │  │  WORKSPACE SCANNER   │  │  DEPENDENCY SCANNER  │       │
│  ├──────────────────────┤  ├──────────────────────┤  ├──────────────────────┤       │
│  │ • Manifest validation │  │ • Prompt injection   │  │ • CVE detection      │      │
│  │ • Schema checking     │  │ • MCP tool extraction│  │ • Typosquatting      │      │
│  │ • Permission audit    │  │ • Code pattern match │  │ • Version checks     │      │
│  │ • Typo detection      │  │ • Zero-width chars   │  │ • Package analysis   │      │
│  │ • Semantic analysis   │  │ • Security patterns  │  │ • Lock verification  │      │
│  └──────────────────────┘  └──────────────────────┘  └──────────────────────┘       │
│           ▲                          ▲                          ▲                   │
│           │                          │                          │                   │
│           └──────────────────────────┴──────────────────────────┘                   │
│                                      │                                              │
└──────────────────────────────────────┴──────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                               SECURITY ANALYZERS                                    │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌─────────────────────────────────┐      ┌─────────────────────────────────┐       │
│  │     TYPO DETECTOR               │      │    SEMANTIC ANALYZER            │       │
│  ├─────────────────────────────────┤      ├─────────────────────────────────┤       │
│  │                                 │      │                                 │       │
│  │  fiIesystem ≈ filesystem        │      │  🤖 OpenAI LLM Analysis         │       │  
│  │  ┌───────────────────┐          │      │  ┌─────────────────────┐        │       │ 
│  │  │ Levenshtein ≤ 2   │          │      │  │ Description:        │        │       │
│  │  │ Dice coefficient  │ ◄─────── ┼──────┼─▶│ "Read-only tool"    │        │       │
│  │  │ Homograph check   │          │      │  │ Schema:             │        │       │
│  │  │ TF-IDF + Cosine   │          │      │  │ {delete: true} ❌   │        │       │
│  │  └───────────────────┘          │      │  └─────────────────────┘        │       │
│  │                                 │      │                                 │       │
│  └─────────────────────────────────┘      └─────────────────────────────────┘       │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                            CRYPTOGRAPHIC SECURITY                                   │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌─────────────────────┐     ┌─────────────────────┐     ┌─────────────────────┐    │
│  │   TOOL HASHING      │     │  SIGSTORE SIGNING   │     │  VERSION TRACKING   │    │
│  ├─────────────────────┤     ├─────────────────────┤     ├─────────────────────┤    │
│  │                     │     │                     │     │                     │    │
│  │  Tool Definition    │     │  ┌──────────────┐   │     │  v1.0 ──► v1.1      │    │
│  │       ↓             │     │  │ DSSE Format  │   │     │    ↓       ↓        │    │
│  │  Canonical JSON     │     │  │ OIDC Auth    │   │     │  Hash₁ ≠ Hash₂      │    │
│  │       ↓             │     │  │ Transparency │   │     │    ↓       ↓        │    │
│  │  SHA-256 Hash       │     │  └──────────────┘   │     │  🔔 Notification    │    │
│  │       ↓             │     │         ↓           │     │    ↓       ↓        │    │
│  │  abc123def456...    │     │    ✓ Verified       │     │  ⚠️  Approval Req   │    │
│  │                     │     │                     │     │                     │    │
│  └─────────────────────┘     └─────────────────────┘     └─────────────────────┘    │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              CHANGE MANAGEMENT                                      │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│   ┌────────────┐     ┌────────────┐     ┌────────────┐     ┌────────────┐           │
│   │  DETECTION │ ──► │   NOTIFY   │ ──► │  APPROVAL  │ ──► │   APPLY    │           │
│   └────────────┘     └────────────┘     └────────────┘     └────────────┘           │
│         │                   │                   │                   │               │
│         ▼                   ▼                   ▼                   ▼               │
│   ╔════════════╗     ╔════════════╗     ╔════════════╗     ╔════════════╗           │
│   ║ Tool Added ║     ║ Risk Level ║     ║ ✓ Approve  ║     ║ Tool Active║           │
│   ║ Perm Change║     ║ Stored DB  ║     ║ ✗ Reject   ║     ║ Or Blocked ║           │
│   ║ Hash Change║     ║ SQLite     ║     ║ CLI/API    ║     ║ Tracked    ║           │
│   ╚════════════╝     ╚════════════╝     ╚════════════╝     ╚════════════╝           │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Installation

```bash
# Install Drift Cop CLI
pip install driftcop

# Clone the repository for web UI
git clone https://github.com/yourusername/drift-cop.git
cd drift-cop
```

### Basic Usage

1. **Scan an MCP Server**:
```bash
driftcop scan-server https://example.com/mcp-server
```

2. **Start the Web UI**:
```bash
cd mcp-sec-web
./start.sh
```

3. **Access the Dashboard**:
- Web UI: http://localhost:5173
- API Docs: http://localhost:8000/docs

## 🔍 Security Checks

### Vulnerability Detection
- **Typosquatting**: Detects lookalike server names (e.g., `fiIesystem` vs `filesystem`)
- **Semantic Drift**: Identifies tools whose capabilities don't match their descriptions
- **Permission Analysis**: Flags excessive or dangerous permissions
- **Prompt Injection**: Detects hidden instructions and malicious patterns
- **Supply Chain**: Scans for known CVEs and unpinned dependencies

### Risk Scoring
Findings are categorized by severity:
- **Critical (10.0)**: Immediate security risk requiring urgent action
- **High (7.0)**: Serious security concern
- **Medium (4.0)**: Moderate risk
- **Low (1.0)**: Minor issue
- **Info (0.0)**: Informational finding

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Drift-Cop                                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────────┐           ┌──────────────────┐              │
│  │  MCP-SEC Scanner │           │  MCP-SEC Web UI  │              │
│  ├──────────────────┤           ├──────────────────┤              │
│  │ • CLI Interface  │           │ • React Frontend │              │
│  │ • Multi-Scanner  │◄─────────►│ • FastAPI Backend│              │
│  │ • Crypto Engine  │           │ • Real-time Dash │              │
│  │ • Report Gen     │           │ • Approval Flow  │              │
│  └────────┬─────────┘           └────────┬─────────┘              │
│           │                               │                         │
│           └──────────────┬────────────────┘                        │
│                          ▼                                          │
│                   ┌──────────────┐                                 │
│                   │ SQLite DBs   │                                 │
│                   ├──────────────┤                                 │
│                   │ • Tracking   │                                 │
│                   │ • Approvals  │                                 │
│                   │ • History    │                                 │
│                   └──────────────┘                                 │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## 📊 Workflow Integration

### CI/CD Pipeline
```yaml
# Example GitHub Actions workflow
- name: Drift Cop Security Scan
  run: |
    driftcop ci-hook https://your-server.com \
      --threshold 5.0 \
      --sarif report.sarif
    
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: report.sarif
```

### Change Management Process
1. **Detection**: Scanner identifies configuration changes
2. **Notification**: Changes tracked in SQLite database
3. **Review**: Security team reviews via web dashboard
4. **Approval**: Approved changes are applied, rejected ones blocked
5. **Audit**: Complete trail maintained for compliance

## 🛡️ Security Best Practices

### For MCP Server Developers
- **Pin Dependencies**: Use exact versions in lock files
- **Sign Manifests**: Use Sigstore for cryptographic signatures
- **Minimize Permissions**: Request only necessary capabilities
- **Clear Descriptions**: Ensure tool descriptions match functionality
- **Regular Scans**: Integrate security scanning in CI/CD

### For Security Teams
- **Regular Monitoring**: Use web dashboard for continuous oversight
- **Risk Thresholds**: Set appropriate thresholds for your environment
- **Approval Workflows**: Establish clear approval processes
- **Audit Trails**: Maintain records for compliance
- **Incident Response**: Have plans for high-severity findings

## 📚 Documentation

- [MCP-SEC CLI Reference](./mcp-sec/README.md)
- [Web UI Guide](./mcp-sec-web/README.md)
- [Integration Guide](./mcp-sec-web/INTEGRATION.md)
- [API Documentation](http://localhost:8000/docs) (when running)

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines for:
- Code style and standards
- Testing requirements
- Pull request process
- Security disclosure policy

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Built for the Model Context Protocol community
- Powered by Tree-sitter for robust code parsing
- Uses Sigstore for supply chain security
- Inspired by best practices from OWASP and security research

---

**Security Notice**: This tool is designed for defensive security purposes only. It helps developers and security teams identify and prevent vulnerabilities in MCP implementations. Always use responsibly and in accordance with applicable laws and regulations.
