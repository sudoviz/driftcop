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

export interface DriftDiff {
  id: string;
  prevContent: string;
  newContent: string;
  addedVerbs: string[];
  removedVerbs: string[];
  rekorProof: boolean;
}

export type SeverityLevel = 'low' | 'medium' | 'high' | 'blocked';
export type Environment = 'prod' | 'staging' | 'dev';