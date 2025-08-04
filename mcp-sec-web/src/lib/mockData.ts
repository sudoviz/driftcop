import { Drift, Repo, Server, DriftDiff } from "@/types/drift";

export const mockRepos: Repo[] = [
  {
    id: "1",
    name: "org/web-api",
    defaultBranch: "main",
    severityThreshold: 1,
  },
  {
    id: "2", 
    name: "org/billing-service",
    defaultBranch: "main",
    severityThreshold: 2,
  },
  {
    id: "3",
    name: "org/auth-service", 
    defaultBranch: "main",
    severityThreshold: 1,
  },
];

export const mockServers: Server[] = [
  {
    id: "1",
    endpoint: "https://api.example.com",
    repoId: "1",
    env: "prod",
    lastScan: "2024-01-15T10:30:00Z",
  },
  {
    id: "2",
    endpoint: "https://staging-api.example.com", 
    repoId: "1",
    env: "staging",
    lastScan: "2024-01-15T09:15:00Z",
  },
  {
    id: "3",
    endpoint: "https://billing.example.com",
    repoId: "2", 
    env: "prod",
    lastScan: "2024-01-15T11:00:00Z",
  },
  {
    id: "4",
    endpoint: "https://auth.example.com",
    repoId: "3",
    env: "prod", 
    lastScan: "2024-01-15T08:45:00Z",
  },
];

export const mockDrifts: Drift[] = [
  {
    id: "drift-1",
    serverId: "1",
    toolName: "billing-service",
    prevDigest: "sha256:abc123def456...",
    newDigest: "sha256:xyz789uvw012...",
    similarity: 0.78,
    severity: 2,
    signerOk: false,
    approved: false,
    createdAt: "2024-01-15T09:30:00Z",
    repo: mockRepos[0],
    server: mockServers[0],
  },
  {
    id: "drift-2", 
    serverId: "2",
    toolName: "user-management",
    prevDigest: "sha256:def456ghi789...",
    newDigest: "sha256:mno345pqr678...", 
    similarity: 0.92,
    severity: 1,
    signerOk: true,
    approved: false,
    createdAt: "2024-01-15T08:15:00Z",
    repo: mockRepos[0],
    server: mockServers[1],
  },
  {
    id: "drift-3",
    serverId: "3", 
    toolName: "payment-processor",
    prevDigest: "sha256:ghi789jkl012...",
    newDigest: "sha256:stu901vwx234...",
    similarity: 0.65,
    severity: 2,
    signerOk: true,
    approved: false,
    createdAt: "2024-01-15T07:45:00Z",
    repo: mockRepos[1],
    server: mockServers[2],
  },
  {
    id: "drift-4",
    serverId: "4",
    toolName: "auth-validator", 
    prevDigest: "sha256:jkl012mno345...",
    newDigest: "sha256:yza678bcd901...",
    similarity: 0.89,
    severity: 0,
    signerOk: true,
    approved: false,
    createdAt: "2024-01-15T06:30:00Z",
    repo: mockRepos[2],
    server: mockServers[3],
  },
  {
    id: "drift-5",
    serverId: "1",
    toolName: "api-gateway",
    prevDigest: "sha256:mno345pqr678...",
    newDigest: "sha256:efg234hij567...",
    similarity: 0.45,
    severity: 3,
    signerOk: false,
    approved: false,
    createdAt: "2024-01-15T05:15:00Z",
    repo: mockRepos[0],
    server: mockServers[0],
  },
];

export const mockDriftDiff: DriftDiff = {
  id: "drift-1",
  prevContent: `# API Configuration
version: "3.8"
services:
  web:
    image: nginx:1.20
    ports:
      - "80:80"
    environment:
      - API_URL=https://old-api.example.com
      - TIMEOUT=30
      - MAX_CONNECTIONS=100
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
    networks:
      - app-network

  redis:
    image: redis:6.2
    ports:
      - "6379:6379"
    environment:
      - REDIS_PASSWORD=oldpassword

networks:
  app-network:
    driver: bridge`,
  newContent: `# API Configuration  
version: "3.8"
services:
  web:
    image: nginx:1.21
    ports:
      - "80:80"
      - "443:443"
    environment:
      - API_URL=https://new-api.example.com
      - TIMEOUT=45
      - MAX_CONNECTIONS=200
      - SSL_ENABLED=true
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    networks:
      - app-network

  redis:
    image: redis:7.0
    ports:
      - "6379:6379"
    environment:
      - REDIS_PASSWORD=newstrongpassword
      - REDIS_MAXMEMORY=512mb

  postgres:
    image: postgres:14
    ports:
      - "5432:5432"
    environment:
      - POSTGRES_DB=appdb
      - POSTGRES_USER=appuser
      - POSTGRES_PASSWORD=securepassword

networks:
  app-network:
    driver: bridge`,
  addedVerbs: ["delete", "update", "create", "migrate"],
  removedVerbs: ["legacy-sync"],
  rekorProof: false,
  // New security analysis fields
  permissionChanges: [
    {
      tool: "billing-service",
      type: "escalated",
      from: ["read"],
      to: ["read", "write", "delete"],
      severity: "critical",
      description: "Tool permissions escalated from read-only to full write/delete access on payment data"
    },
    {
      tool: "user-management",
      type: "added",
      to: ["spawn", "network"],
      severity: "high",
      description: "New dangerous permissions added: ability to spawn processes and make network calls"
    },
    {
      tool: "analytics-viewer",
      type: "removed",
      from: ["write"],
      severity: "low",
      description: "Write permission removed, tool is now read-only which improves security"
    }
  ],
  semanticAnalysis: [
    {
      tool: "billing-service",
      descriptionMatch: false,
      claimedCapabilities: "Read-only access to view billing information and generate reports",
      actualCapabilities: "Full CRUD operations on payment methods, billing records, and financial data",
      mismatchDetails: [
        "Claims to be read-only but has write/delete permissions",
        "Can modify payment methods despite description saying 'view only'",
        "Has access to sensitive PII not mentioned in description"
      ],
      riskScore: 8.5
    },
    {
      tool: "user-management",
      descriptionMatch: true,
      claimedCapabilities: "Manage user accounts, roles, and permissions",
      actualCapabilities: "Create, update, delete users and manage role assignments",
      riskScore: 3.2
    },
    {
      tool: "analytics-viewer",
      descriptionMatch: false,
      claimedCapabilities: "Simple analytics dashboard for viewing metrics",
      actualCapabilities: "Complex data processing with ability to execute custom queries and export data",
      mismatchDetails: [
        "Can execute arbitrary SQL queries not mentioned in description",
        "Has data export capabilities that could lead to data exfiltration"
      ],
      riskScore: 6.8
    }
  ],
  securityFindings: [
    {
      type: "excessive_permissions",
      severity: "critical",
      tool: "billing-service",
      description: "Tool has write/delete permissions on sensitive financial data but claims to be read-only",
      location: "manifest.json:45",
      remediation: "Restrict permissions to read-only or update description to accurately reflect capabilities"
    },
    {
      type: "hardcoded_secret",
      severity: "high",
      description: "Database password is hardcoded in the configuration file",
      location: "docker-compose.yml:38",
      remediation: "Use environment variables or secret management service instead of hardcoded credentials"
    },
    {
      type: "typosquatting",
      severity: "medium",
      tool: "fiIesystem",
      description: "Tool name 'fiIesystem' (with capital I) is suspiciously similar to 'filesystem'",
      location: "manifest.json:72",
      remediation: "Verify this is the intended tool name and not a typosquatting attempt"
    },
    {
      type: "vulnerable_dependency",
      severity: "high",
      description: "nginx:1.20 has known vulnerabilities (CVE-2021-23017)",
      location: "docker-compose.yml:6",
      remediation: "Update to nginx:1.21 or later to patch security vulnerabilities"
    },
    {
      type: "prompt_injection",
      severity: "medium",
      description: "Tool description contains hidden Unicode characters that could manipulate LLM behavior",
      location: "manifest.json:89",
      remediation: "Remove zero-width characters and Unicode manipulation from tool descriptions"
    }
  ],
  overallRiskScore: 7.8,
  securitySummary: {
    criticalFindings: 1,
    highFindings: 2,
    mediumFindings: 2,
    lowFindings: 0
  }
};