export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'DENY';

export interface RiskResult {
  level: RiskLevel;
  reason: string;
  requiresApproval: boolean;
}

export interface RiskPolicy {
  immutable?: string[];
  protectedPaths?: string[];
  sensitiveAreas?: string[];
  highRiskExtensions?: Set<string> | string[];
  mediumDiffBytes?: number;
  caseSensitive?: boolean;
}

export interface AgentSafeFSOptions {
  root: string;
  policy?: RiskPolicy;
  operationTtlMs?: number;
  auditPath?: string | null;
  snapshotDir?: string;
  clock?: () => number;
  newFileMode?: number;
}

export interface WriteProposal {
  operationId: string;
  operation: 'write';
  path: string;
  expiresAtMs: number;
  sha256Before: string | null;
  sha256After: string;
  bytesBefore: number;
  bytesAfter: number;
  existedBefore: boolean;
  risk: RiskResult;
}

export interface CommitResult {
  operationId: string;
  operation: 'write';
  path: string;
  committedAt: string;
  sha256Before: string | null;
  sha256After: string;
  snapshotCreated: boolean;
  existedBefore: boolean;
  risk: RiskResult;
}

export interface RollbackResult {
  operationId: string;
  path: string;
  rolledBackAt: string;
  sha256Restored: string | null;
}

export class AgentSafeFSError extends Error {
  code: string;
  details: unknown;
  constructor(code: string, message: string, details?: unknown);
}

export class AgentSafeFS {
  constructor(options: AgentSafeFSOptions);
  proposeWrite(input: { path: string; content: string | Uint8Array }): WriteProposal;
  commit(operationId: string, options?: { confirmedPath?: string | null }): CommitResult;
  rollback(operationId: string, options?: { confirmedPath?: string | null }): RollbackResult;
}

export function sha256(buffer: Uint8Array): string;

export function resolveSafePath(options: {
  root: string;
  inputPath: string;
  denySecretLikeNames?: boolean;
  secretPatterns?: RegExp[];
  allowTargetDirectory?: boolean;
}): string;

export function classifyRisk(options: {
  relativePath: string;
  operation?: 'write' | 'delete' | 'move';
  diffBytes?: number;
  immutable?: string[];
  protectedPaths?: string[];
  sensitiveAreas?: string[];
  highRiskExtensions?: Set<string> | string[];
  mediumDiffBytes?: number;
  caseSensitive?: boolean;
}): RiskResult;

export const DEFAULT_HIGH_RISK_EXTENSIONS: readonly string[];
