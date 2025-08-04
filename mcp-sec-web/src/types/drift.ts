export interface Repo {
  id: string;
  name: string;
  defaultBranch: string;
  severityThreshold: number;
}

export interface Server {
  id: string;
  endpoint: string;
  repoId: string;
  env: 'prod' | 'staging' | 'dev';
  lastScan: string;
}

export interface Drift {
  id: string;
  serverId: string;
  toolName: string;
  prevDigest: string;
  newDigest: string;
  similarity: number;
  severity: 0 | 1 | 2 | 3; // LOW, MED, HIGH, BLOCKED
  signerOk: boolean;
  approved: boolean;
  approver?: string;
  approverNote?: string;
  createdAt: string;
  resolvedAt?: string;
  // Computed fields for UI
  repo?: Repo;
  server?: Server;
  age?: string;
}

export interface PermissionChange {
  tool: string;
  type: 'added' | 'removed' | 'escalated';
  from?: string[];
  to?: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
}

export interface SemanticAnalysis {
  tool: string;
  descriptionMatch: boolean;
  claimedCapabilities: string;
  actualCapabilities: string;
  mismatchDetails?: string[];
  riskScore: number;
}

export interface SecurityFinding {
  type: 'typosquatting' | 'prompt_injection' | 'hardcoded_secret' | 'vulnerable_dependency' | 'excessive_permissions';
  severity: 'low' | 'medium' | 'high' | 'critical';
  tool?: string;
  description: string;
  location?: string;
  remediation?: string;
}

export interface DriftDiff {
  id: string;
  prevContent: string;
  newContent: string;
  addedVerbs: string[];
  removedVerbs: string[];
  rekorProof: boolean;
  // New security analysis fields
  permissionChanges: PermissionChange[];
  semanticAnalysis: SemanticAnalysis[];
  securityFindings: SecurityFinding[];
  overallRiskScore: number;
  securitySummary: {
    criticalFindings: number;
    highFindings: number;
    mediumFindings: number;
    lowFindings: number;
  };
}

export type SeverityLevel = 'low' | 'medium' | 'high' | 'blocked';
export type Environment = 'prod' | 'staging' | 'dev';