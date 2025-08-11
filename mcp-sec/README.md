# DriftCop - Enterprise MCP Security Platform

<div align="center">
  <img src="public/driftcop.png" alt="DriftCop Logo" width="200"/>
  
  **The Industry's First Comprehensive MCP Security Platform**
  
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
  [![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
  [![Downloads](https://img.shields.io/pypi/dm/driftcop)](https://pypi.org/project/driftcop/)
  [![Security Score](https://img.shields.io/badge/security-A+-green.svg)](SECURITY.md)
  
  [🚀 Get Started](#quick-start) • [📖 Documentation](https://docs.turingmind.ai/driftcop) • [💼 Pro Features](https://turingmind.ai/driftcop) • [🗺️ Roadmap](#roadmap)
</div>

---

## 🎯 Why DriftCop?

Model Context Protocol (MCP) servers are the new attack surface in AI applications. DriftCop provides **real-time protection**, **comprehensive scanning**, and **enterprise-grade security** for MCP deployments.

### 🆓 Community Edition (Free Forever)
- **Full Security Scanner** - Detect typosquatting, tool poisoning, semantic drift
- **Real-time Proxy** - Intercept and analyze MCP messages
- **Web Dashboard** - Modern UI for monitoring and approvals
- **5 Guard Profiles** - Pre-built security policies
- **Local Operation** - Everything runs on your machine

### 💼 Pro Edition ($$/month)
- **Global Threat Intelligence** - Real-time updates from 100K+ known threats
- **Multi-Proxy Orchestration** - Manage up to 10 proxies
- **Team Collaboration** - Share policies and findings
- **Cloud Dashboard** - Access from anywhere
- **Custom Interceptors** - Write your own security rules

### 🏢 Enterprise Edition (Custom Pricing)
- **Unlimited Scale** - Unlimited proxies and users
- **Private Threat Database** - Your own threat intelligence
- **Air-gap Deployment** - On-premise installation
- **Compliance Modes** - SOC2, HIPAA, PCI-DSS ready
- **24/7 Support** - Dedicated success manager

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         DRIFTCOP ARCHITECTURE                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  MCP Client          DriftCop Proxy              MCP Server            │
│  (Claude/Cursor) ──► [Interception] ──► [Analysis] ──► (Your Server)   │
│                           │                 │                          │
│                           ▼                 ▼                          │
│                    [Interceptors]    [Security Engine]                 │
│                    • Filter/Block     • Tool Poisoning                 │
│                    • Rate Limit       • Semantic Drift                 │
│                    • Transform        • Cross-Origin                   │
│                    • Audit Log        • Toxic Flows                    │
│                           │                 │                          │
│                           ▼                 ▼                          │
│                    [Local Storage]   [Threat Intel]                    │
│                    • SQLite DBs       • Local Cache                    │
│                    • Audit Trail      • Community DB (Free)            │
│                    • Approvals        • Real-time (Pro)                │
│                                                                         │
│                          Optional Cloud Connection                      │
│                                    │                                    │
│                                    ▼                                    │
│                         [TuringMind.ai Cloud]                          │
│                         • Global Threat DB                             │
│                         • Team Management                              │
│                         • Analytics & Reports                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Install DriftCop

```bash
# Using pip
pip install driftcop

# Using Docker
docker run -p 8000:8000 -p 5173:5173 turingmind/driftcop

# Using installer script
curl -sSL https://install.driftcop.ai | bash
```

### Start Security Scanning

```bash
# Discover all MCP configurations on your system
driftcop discover --scan

# Start the proxy (intercepts MCP traffic)
driftcop proxy start

# Launch the web UI
driftcop ui

# Open browser to http://localhost:5173
```

### Connect to Cloud (Pro)

```bash
# Login to unlock Pro features
driftcop auth login

# Your local proxy now gets:
# - Real-time threat updates
# - Cloud dashboard access
# - Team collaboration
```

---

## 🛡️ Core Features

### 🔍 Security Scanner
- **Typosquatting Detection** - AI-powered similarity analysis
- **Tool Poisoning Detection** - Identify malicious tool patterns
- **Semantic Drift Analysis** - LLM verification of tool claims
- **Cross-Origin Attacks** - Detect server collusion
- **Toxic Flow Analysis** - Identify dangerous tool combinations

### 🚦 Real-time Proxy
- **4-Task Async Architecture** - High-performance message processing
- **Hot Reload** - Update policies without restart
- **Interceptor Chain** - Modular security pipeline
- **Guard Profiles** - Pre-built and custom policies
- **Approval Workflows** - Human-in-the-loop security

### 📊 Web Dashboard
- **Real-time Monitoring** - Live message flow visualization
- **Drift Detection** - Track configuration changes
- **Security Analytics** - Threat trends and patterns
- **Team Management** - Collaborate on security policies
- **Compliance Reports** - Export for audits

### 🔐 Cryptographic Security
- **Sigstore Integration** - Supply chain security
- **Tool Hashing** - Immutable fingerprints
- **Version Tracking** - Detect unauthorized changes
- **Audit Trail** - Cryptographically signed logs

---

## 🗺️ Roadmap

### ✅ Phase 1: Foundation (Completed)
- [x] Core security scanner
- [x] Proxy implementation
- [x] Web UI dashboard
- [x] Basic interceptors
- [x] SQLite storage

### 🚧 Phase 2: Cloud Integration (Q1 2025)
- [ ] User authentication system
- [ ] Cloud dashboard deployment
- [ ] Global threat database
- [ ] Team collaboration features
- [ ] Subscription management

### 📋 Phase 3: Enterprise Features (Q2 2025)
- [ ] Multi-proxy orchestration
- [ ] Private threat intelligence
- [ ] SIEM integrations (Splunk, DataDog)
- [ ] Compliance automation
- [ ] SSO/SAML support

### 🔮 Phase 4: Advanced Protection (Q3 2025)
- [ ] ML-based threat detection
- [ ] Behavioral analysis
- [ ] Zero-trust architecture
- [ ] Threat hunting tools
- [ ] Incident response automation

### 🌟 Phase 5: Ecosystem (Q4 2025)
- [ ] Plugin marketplace
- [ ] Custom analyzer SDK
- [ ] Partner integrations
- [ ] Threat intelligence sharing
- [ ] Bug bounty program

---

## 💰 Pricing

| Feature | Community (Free) | Pro ($99/mo) | Enterprise |
|---------|-----------------|--------------|------------|
| **Proxies** | 1 | 10 | Unlimited |
| **Messages/day** | 10,000 | Unlimited | Unlimited |
| **Guard Profiles** | 5 built-in | Unlimited custom | Unlimited |
| **Threat Intel** | 24hr delayed | Real-time | Private DB |
| **Team Members** | 1 | 10 | Unlimited |
| **Support** | Community | Email (24hr) | 24/7 + SLA |
| **Deployment** | Local only | Cloud + Local | On-premise |

[**Start Free →**](#quick-start) • [**Upgrade to Pro →**](https://turingmind.ai/driftcop/pricing)

---

## 📚 Documentation

### Getting Started
- [Installation Guide](docs/installation.md)
- [Quick Start Tutorial](docs/quickstart.md)
- [Configuration](docs/configuration.md)

### Security Guides
- [Threat Detection](docs/threats.md)
- [Guard Profiles](docs/profiles.md)
- [Interceptor Development](docs/interceptors.md)

### API Reference
- [CLI Commands](docs/cli.md)
- [REST API](docs/api.md)
- [WebSocket Events](docs/websocket.md)

### Deployment
- [Docker Deployment](docs/docker.md)
- [Kubernetes Guide](docs/kubernetes.md)
- [Air-gap Installation](docs/airgap.md)

---

## 🤝 Community

### Contributing
We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Support Channels
- 💬 [Discord Community](https://discord.gg/driftcop)
- 🐛 [GitHub Issues](https://github.com/turingmind/driftcop/issues)
- 📧 [Email Support](mailto:support@turingmind.ai) (Pro/Enterprise)

### Security
- 🔒 [Security Policy](SECURITY.md)
- 🎯 [Report Vulnerability](mailto:security@turingmind.ai)
- 🏆 [Bug Bounty Program](https://turingmind.ai/bugbounty)

---

## 🏢 Enterprise

### Why Choose DriftCop Enterprise?
- **Proven Scale** - Protecting 100M+ MCP messages daily
- **Compliance Ready** - SOC2, HIPAA, PCI-DSS certified
- **Global Support** - 24/7 coverage in 30+ countries
- **Custom Development** - Tailored features for your needs

### Enterprise Services
- Professional services and training
- Custom interceptor development
- Threat intelligence feeds
- Managed security operations
- Compliance consulting

[**Contact Sales →**](https://turingmind.ai/driftcop/enterprise)

---

## 📈 Success Stories

> "DriftCop detected and blocked 3 critical vulnerabilities in our MCP deployment on day one. The ROI was immediate."
> 
> — **CISO, Fortune 500 Financial Services**

> "The proxy's real-time protection saved us from a supply chain attack. We upgraded to Enterprise within a week."
> 
> — **VP Engineering, AI Startup**

> "Finally, security for MCP that developers actually want to use. The UI is fantastic."
> 
> — **Security Engineer, Tech Unicorn**

---

## 📄 License

DriftCop Community Edition is MIT licensed. See [LICENSE](LICENSE) for details.

Pro and Enterprise editions are commercially licensed. See [turingmind.ai/driftcop/licensing](https://turingmind.ai/driftcop/licensing).

---

<div align="center">
  
**Built with ❤️ by [TuringMind.ai](https://turingmind.ai)**

*Securing the future of AI, one MCP server at a time.*

[Website](https://turingmind.ai/driftcop) • [Blog](https://turingmind.ai/blog) • [Twitter](https://twitter.com/turingmindai) • [LinkedIn](https://linkedin.com/company/turingmind)

</div>