import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fail } from './errors.mjs';
import { resolveSafePath, toPortableRelative, isInside } from './path-safety.mjs';
import { classifyRisk, isValidPolicyPrefix } from './policy.mjs';

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function readBufferOrNull(filePath) {
  try {
    return fs.readFileSync(filePath);
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

function openWriteSync(filePath, mode = 0o600) {
  return fs.openSync(filePath, 'wx', mode);
}

function writeAndSync(fd, buffer) {
  fs.writeFileSync(fd, buffer);
  fs.fsyncSync(fd);
}

function bestEffortDirectorySync(directory) {
  if (process.platform === 'win32') return;
  let fd;
  try {
    fd = fs.openSync(directory, 'r');
    fs.fsyncSync(fd);
  } catch {
    // Directory fsync is not uniformly supported across filesystems.
  } finally {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch {}
    }
  }
}

const NO_EXPECTATION = Symbol('NO_EXPECTATION');

function atomicWrite({
  root,
  filePath,
  buffer,
  pathOptions,
  newFileMode = 0o600,
  expectedCurrentSha = NO_EXPECTATION,
  conflictCode = 'CONFLICT_CHANGED_DURING_COMMIT',
}) {
  // Validate both before and after creating missing parents. This closes the
  // common static junction/symlink escape through a non-existing descendant.
  resolveSafePath({ root, inputPath: filePath, ...pathOptions });
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  resolveSafePath({ root, inputPath: filePath, ...pathOptions });

  const existingStat = fs.lstatSync(filePath, { throwIfNoEntry: false });
  const preservedMode = existingStat?.isFile() ? (existingStat.mode & 0o777) : null;
  const temp = path.join(path.dirname(filePath), `.${path.basename(filePath)}.${crypto.randomUUID()}.tmp`);
  let fd;
  try {
    fd = openWriteSync(temp, preservedMode ?? newFileMode);
    if (process.platform !== 'win32' && preservedMode !== null) fs.fchmodSync(fd, preservedMode);
    writeAndSync(fd, buffer);
    fs.closeSync(fd);
    fd = undefined;

    // Re-check immediately before replacement in case the directory tree
    // changed after the earlier validation.
    resolveSafePath({ root, inputPath: filePath, ...pathOptions });
    resolveSafePath({ root, inputPath: temp, denySecretLikeNames: false, ...pathOptions });
    if (expectedCurrentSha !== NO_EXPECTATION) {
      const live = readBufferOrNull(filePath);
      const liveSha = live === null ? null : sha256(live);
      if (liveSha !== expectedCurrentSha) {
        fail(conflictCode, 'Target changed during the final mutation window', {
          expectedSha256: expectedCurrentSha,
          actualSha256: liveSha,
        });
      }
    }
    fs.renameSync(temp, filePath);
    bestEffortDirectorySync(path.dirname(filePath));
  } catch (error) {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch {}
    }
    bestEffortSafeRemove({ root, filePath: temp, pathOptions });
    throw error;
  }
}

function bestEffortSafeRemove({ root, filePath, pathOptions }) {
  try {
    const safePath = resolveSafePath({
      root,
      inputPath: filePath,
      denySecretLikeNames: false,
      ...pathOptions,
    });
    fs.rmSync(safePath, { force: true });
  } catch {
    // Cleanup must never follow a newly introduced alias. Leaving an orphaned
    // internal file is safer than deleting through an unsafe path.
  }
}

function appendAuditStrict({ root, auditPath, entry, pathOptions }) {
  if (!auditPath) return;
  resolveSafePath({ root, inputPath: auditPath, denySecretLikeNames: false, ...pathOptions });
  fs.mkdirSync(path.dirname(auditPath), { recursive: true });
  resolveSafePath({ root, inputPath: auditPath, denySecretLikeNames: false, ...pathOptions });

  let fd;
  try {
    fd = fs.openSync(auditPath, 'a', 0o600);
    fs.writeFileSync(fd, JSON.stringify(entry) + os.EOL, 'utf8');
    fs.fsyncSync(fd);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function nowIso() {
  return new Date().toISOString();
}

function readClock(clock) {
  const value = clock();
  if (!Number.isFinite(value)) fail('CLOCK_INVALID', 'clock() must return a finite millisecond value');
  return value;
}

function serializeError(error) {
  return {
    name: error?.name ?? 'Error',
    code: error?.code ?? null,
    message: error?.message ?? String(error),
  };
}

function samePath(left, right, caseSensitive) {
  const a = path.resolve(left).normalize('NFC');
  const b = path.resolve(right).normalize('NFC');
  return caseSensitive ? a === b : a.toLocaleLowerCase('en-US') === b.toLocaleLowerCase('en-US');
}

function clonePolicy(policy) {
  if (policy === null || typeof policy !== 'object' || Array.isArray(policy)) {
    fail('CONFIG_INVALID', 'policy must be an object');
  }
  const allowedKeys = new Set([
    'immutable',
    'protectedPaths',
    'sensitiveAreas',
    'highRiskExtensions',
    'mediumDiffBytes',
    'caseSensitive',
  ]);
  const unknownKeys = Object.keys(policy).filter((key) => !allowedKeys.has(key));
  if (unknownKeys.length > 0) {
    fail('CONFIG_INVALID', 'Unknown policy option', { unknownKeys });
  }
  const copy = { ...policy };
  for (const key of ['immutable', 'protectedPaths', 'sensitiveAreas']) {
    if (copy[key] !== undefined) {
      if (!Array.isArray(copy[key]) || copy[key].some((value) => !isValidPolicyPrefix(value))) {
        fail('CONFIG_INVALID', `${key} must contain safe non-empty relative path prefixes`);
      }
      copy[key] = [...copy[key]];
    }
  }
  if (copy.highRiskExtensions !== undefined) {
    if (!(copy.highRiskExtensions instanceof Set) && !Array.isArray(copy.highRiskExtensions)) {
      fail('CONFIG_INVALID', 'highRiskExtensions must be a Set or array of strings');
    }
    const values = [...copy.highRiskExtensions];
    if (values.some((value) => typeof value !== 'string' || value.length === 0)) {
      fail('CONFIG_INVALID', 'highRiskExtensions must contain non-empty strings');
    }
    copy.highRiskExtensions = new Set(values.map((value) => {
      const lower = value.toLowerCase();
      return lower.startsWith('.') ? lower : `.${lower}`;
    }));
  }
  if (copy.mediumDiffBytes !== undefined && (!Number.isFinite(copy.mediumDiffBytes) || copy.mediumDiffBytes < 0)) {
    fail('CONFIG_INVALID', 'mediumDiffBytes must be a non-negative finite number');
  }
  if (copy.caseSensitive !== undefined && typeof copy.caseSensitive !== 'boolean') {
    fail('CONFIG_INVALID', 'caseSensitive must be boolean');
  }
  return copy;
}

function publicRisk(risk) {
  return { level: risk.level, reason: risk.reason, requiresApproval: risk.requiresApproval };
}

function publicProposal(proposal) {
  return {
    operationId: proposal.operationId,
    operation: proposal.operation,
    path: proposal.approvalPath,
    expiresAtMs: proposal.expiresAtMs,
    sha256Before: proposal.sha256Before,
    sha256After: proposal.sha256After,
    bytesBefore: proposal.bytesBefore,
    bytesAfter: proposal.bytesAfter,
    existedBefore: proposal.existedBefore,
    risk: publicRisk(proposal.risk),
  };
}

function publicCommitRecord(record) {
  return {
    operationId: record.operationId,
    operation: record.operation,
    path: record.approvalPath,
    committedAt: record.committedAt,
    sha256Before: record.sha256Before,
    sha256After: record.sha256After,
    snapshotCreated: Boolean(record.snapshotPath),
    existedBefore: record.existedBefore,
    risk: publicRisk(record.risk),
  };
}

export class AgentSafeFS {
  #pending = new Map();
  #committed = new Map();
  #root;
  #policy;
  #caseSensitive;
  #operationTtlMs;
  #auditPath;
  #snapshotRoot;
  #clock;
  #pathOptions;
  #newFileMode;

  constructor(options = {}) {
    if (options === null || typeof options !== 'object' || Array.isArray(options)) {
      fail('CONFIG_INVALID', 'options must be an object');
    }
    const allowedKeys = new Set([
      'root',
      'policy',
      'operationTtlMs',
      'auditPath',
      'snapshotDir',
      'clock',
      'newFileMode',
    ]);
    const unknownKeys = Object.keys(options).filter((key) => !allowedKeys.has(key));
    if (unknownKeys.length > 0) {
      fail('CONFIG_INVALID', 'Unknown AgentSafeFS option', { unknownKeys });
    }
    const {
      root,
      policy = {},
      operationTtlMs = 5 * 60_000,
      auditPath = null,
      snapshotDir = '.agentsafefs/snapshots',
      clock = () => Date.now(),
      newFileMode = 0o600,
    } = options;

    if (typeof root !== 'string' || root.length === 0 || root.includes('\0')) {
      fail('CONFIG_INVALID', 'root must be a non-empty string without NUL bytes');
    }
    if (auditPath !== null && (typeof auditPath !== 'string' || auditPath.length === 0 || auditPath.includes('\0'))) {
      fail('CONFIG_INVALID', 'auditPath must be null or a non-empty string without NUL bytes');
    }
    if (typeof snapshotDir !== 'string' || snapshotDir.length === 0 || snapshotDir.includes('\0')) {
      fail('CONFIG_INVALID', 'snapshotDir must be a non-empty string without NUL bytes');
    }
    if (!Number.isFinite(operationTtlMs) || operationTtlMs <= 0) {
      fail('CONFIG_INVALID', 'operationTtlMs must be a positive finite number');
    }
    if (typeof clock !== 'function') fail('CONFIG_INVALID', 'clock must be a function');
    if (!Number.isInteger(newFileMode) || newFileMode < 0 || newFileMode > 0o777) {
      fail('CONFIG_INVALID', 'newFileMode must be an integer between 0 and 0o777');
    }

    const requestedRoot = path.resolve(root);
    const rootStat = fs.lstatSync(requestedRoot, { throwIfNoEntry: false });
    if (!rootStat) fail('ROOT_NOT_FOUND', 'Configured root does not exist');
    if (rootStat.isSymbolicLink()) fail('ROOT_SYMLINK_DENIED', 'Configured root may not be a symlink or junction');
    if (!rootStat.isDirectory()) fail('ROOT_NOT_DIRECTORY', 'Configured root must be a directory');

    this.#root = fs.realpathSync.native(requestedRoot);
    this.#policy = clonePolicy(policy);
    if ((process.platform === 'win32' || process.platform === 'darwin') && this.#policy.caseSensitive === true) {
      fail('CONFIG_INVALID', 'caseSensitive=true is unsafe and unsupported on Windows and macOS');
    }
    this.#caseSensitive = (process.platform === 'win32' || process.platform === 'darwin')
      ? false
      : (this.#policy.caseSensitive ?? true);
    this.#operationTtlMs = operationTtlMs;
    this.#clock = clock;
    this.#pathOptions = Object.freeze({ caseSensitive: this.#caseSensitive });
    this.#newFileMode = newFileMode;

    this.#snapshotRoot = resolveSafePath({
      root: this.#root,
      inputPath: snapshotDir,
      denySecretLikeNames: false,
      allowTargetDirectory: true,
      ...this.#pathOptions,
    });
    if (samePath(this.#snapshotRoot, this.#root, this.#caseSensitive)) {
      fail('CONFIG_INVALID', 'snapshotDir may not be the workspace root');
    }
    const snapshotStat = fs.lstatSync(this.#snapshotRoot, { throwIfNoEntry: false });
    if (snapshotStat && !snapshotStat.isDirectory()) {
      fail('CONFIG_INVALID', 'snapshotDir must be a directory path');
    }

    this.#auditPath = auditPath
      ? resolveSafePath({ root: this.#root, inputPath: auditPath, denySecretLikeNames: false, ...this.#pathOptions })
      : null;

    if (this.#auditPath && (
      isInside(this.#snapshotRoot, this.#auditPath, { caseSensitive: this.#caseSensitive }) ||
      isInside(this.#auditPath, this.#snapshotRoot, { caseSensitive: this.#caseSensitive })
    )) {
      fail('CONFIG_INVALID', 'auditPath and snapshotDir may not overlap');
    }
  }

  #assertNotReserved(absolutePath) {
    if (
      isInside(this.#snapshotRoot, absolutePath, { caseSensitive: this.#caseSensitive }) ||
      isInside(absolutePath, this.#snapshotRoot, { caseSensitive: this.#caseSensitive })
    ) {
      fail('PATH_RESERVED_INTERNAL', 'Snapshot storage and its parent path are reserved for AgentSafeFS');
    }
    if (this.#auditPath && (
      isInside(this.#auditPath, absolutePath, { caseSensitive: this.#caseSensitive }) ||
      isInside(absolutePath, this.#auditPath, { caseSensitive: this.#caseSensitive })
    )) {
      fail('PATH_RESERVED_INTERNAL', 'Audit log path and its parent path are reserved for AgentSafeFS');
    }
  }

  #resolveTarget(inputPath) {
    const absolutePath = resolveSafePath({ root: this.#root, inputPath, ...this.#pathOptions });
    this.#assertNotReserved(absolutePath);
    return absolutePath;
  }

  #confirmationMatches(confirmedPath, expectedAbsolutePath) {
    if (typeof confirmedPath !== 'string' || confirmedPath.length === 0) return false;
    try {
      const confirmedAbsolute = this.#resolveTarget(confirmedPath);
      const approvalCaseSensitive = process.platform !== 'win32';
      const expected = approvalCaseSensitive ? expectedAbsolutePath : expectedAbsolutePath.toLocaleLowerCase('en-US');
      const actual = approvalCaseSensitive ? confirmedAbsolute : confirmedAbsolute.toLocaleLowerCase('en-US');
      return actual === expected;
    } catch {
      return false;
    }
  }

  #createSnapshot(operationId, current) {
    resolveSafePath({ root: this.#root, inputPath: this.#snapshotRoot, denySecretLikeNames: false, allowTargetDirectory: true, ...this.#pathOptions });
    fs.mkdirSync(this.#snapshotRoot, { recursive: true });
    resolveSafePath({ root: this.#root, inputPath: this.#snapshotRoot, denySecretLikeNames: false, allowTargetDirectory: true, ...this.#pathOptions });
    const snapshotPath = path.join(this.#snapshotRoot, `${operationId}.bin`);
    resolveSafePath({ root: this.#root, inputPath: snapshotPath, denySecretLikeNames: false, ...this.#pathOptions });

    let fd;
    let created = false;
    try {
      fd = openWriteSync(snapshotPath);
      created = true;
      writeAndSync(fd, current);
      fs.closeSync(fd);
      fd = undefined;
      bestEffortDirectorySync(this.#snapshotRoot);
    } catch (error) {
      if (fd !== undefined) {
        try { fs.closeSync(fd); } catch {}
      }
      if (created) {
        bestEffortSafeRemove({ root: this.#root, filePath: snapshotPath, pathOptions: this.#pathOptions });
      }
      throw error;
    }
    return { snapshotPath, snapshotSha256: sha256(current) };
  }

  #restorePreCommitState({
    absolutePath,
    existedBefore,
    beforeBuffer,
    expectedCurrentSha,
    pathOptions = this.#pathOptions,
  }) {
    if (existedBefore) {
      atomicWrite({
        root: this.#root,
        filePath: absolutePath,
        buffer: beforeBuffer,
        pathOptions,
        newFileMode: this.#newFileMode,
        expectedCurrentSha,
        conflictCode: 'COMMIT_RECOVERY_CONFLICT',
      });
    } else {
      const target = resolveSafePath({ root: this.#root, inputPath: absolutePath, ...pathOptions });
      const live = readBufferOrNull(target);
      const liveSha = live === null ? null : sha256(live);
      if (liveSha !== expectedCurrentSha) {
        fail('COMMIT_RECOVERY_CONFLICT', 'Target changed before commit recovery could remove it', {
          expectedSha256: expectedCurrentSha,
          actualSha256: liveSha,
        });
      }
      fs.rmSync(target, { force: true });
      bestEffortDirectorySync(path.dirname(target));
    }
  }

  proposeWrite({ path: inputPath, content }) {
    if (typeof content !== 'string' && !(content instanceof Uint8Array)) {
      fail('CONTENT_INVALID', 'content must be a string or Uint8Array');
    }

    const absolutePath = this.#resolveTarget(inputPath);
    const relativePath = path.relative(this.#root, absolutePath);
    const approvalPath = toPortableRelative(this.#root, absolutePath);
    const before = readBufferOrNull(absolutePath);
    const after = typeof content === 'string' ? Buffer.from(content, 'utf8') : Buffer.from(content);
    const diffBytes = Math.max(before?.length ?? 0, after.length);
    const risk = classifyRisk({
      relativePath,
      operation: 'write',
      diffBytes,
      ...this.#policy,
      caseSensitive: this.#caseSensitive,
    });

    if (risk.level === 'DENY') {
      fail('POLICY_DENIED', 'Policy denied this path', { path: approvalPath, reason: risk.reason });
    }

    const operationId = crypto.randomUUID();
    const createdAtMs = readClock(this.#clock);
    const proposal = {
      operationId,
      operation: 'write',
      approvalPath,
      absolutePath,
      createdAtMs,
      expiresAtMs: createdAtMs + this.#operationTtlMs,
      sha256Before: before === null ? null : sha256(before),
      sha256After: sha256(after),
      bytesBefore: before?.length ?? 0,
      bytesAfter: after.length,
      existedBefore: before !== null,
      risk,
      content: after,
    };

    this.#pending.set(operationId, proposal);
    return publicProposal(proposal);
  }

  commit(operationId, { confirmedPath = null } = {}) {
    const proposal = this.#pending.get(operationId);
    if (!proposal) fail('OPERATION_NOT_PENDING', 'Unknown, expired, or already committed operation');
    if (readClock(this.#clock) >= proposal.expiresAtMs) {
      this.#pending.delete(operationId);
      fail('OPERATION_EXPIRED', 'Operation has expired');
    }

    if (proposal.risk.requiresApproval && !this.#confirmationMatches(confirmedPath, proposal.absolutePath)) {
      fail('APPROVAL_REQUIRED', 'Approval must confirm the exact proposed target', {
        expectedPath: proposal.approvalPath,
      });
    }

    // Re-resolve from the canonical approval path at commit time so a junction
    // introduced after propose cannot inherit a stale trusted absolute path.
    const absolutePath = this.#resolveTarget(proposal.approvalPath);
    const current = readBufferOrNull(absolutePath);
    const currentSha = current === null ? null : sha256(current);
    if (currentSha !== proposal.sha256Before) {
      fail('CONFLICT_CHANGED_SINCE_PROPOSE', 'File changed after proposal was created', {
        expectedSha256: proposal.sha256Before,
        actualSha256: currentSha,
      });
    }

    let snapshotPath = null;
    let snapshotSha256 = null;
    if (current !== null) {
      ({ snapshotPath, snapshotSha256 } = this.#createSnapshot(operationId, current));
    }

    let mutationApplied = false;
    try {
      atomicWrite({
        root: this.#root,
        filePath: absolutePath,
        buffer: proposal.content,
        pathOptions: this.#pathOptions,
        newFileMode: this.#newFileMode,
        expectedCurrentSha: proposal.sha256Before,
      });
      mutationApplied = true;

      const verified = fs.readFileSync(absolutePath);
      const verifiedSha = sha256(verified);
      if (verifiedSha !== proposal.sha256After) {
        fail('VERIFY_FAILED', 'Readback verification failed after commit');
      }

      const record = {
        operationId,
        operation: 'write',
        approvalPath: proposal.approvalPath,
        absolutePath,
        committedAt: nowIso(),
        sha256Before: proposal.sha256Before,
        sha256After: verifiedSha,
        snapshotPath,
        snapshotSha256,
        existedBefore: proposal.existedBefore,
        risk: proposal.risk,
        contentAfter: Buffer.from(proposal.content),
      };

      appendAuditStrict({
        root: this.#root,
        auditPath: this.#auditPath,
        pathOptions: this.#pathOptions,
        entry: {
          event: 'commit',
          operationId,
          operation: 'write',
          path: proposal.approvalPath,
          committedAt: record.committedAt,
          sha256Before: record.sha256Before,
          sha256After: record.sha256After,
          existedBefore: record.existedBefore,
          risk: publicRisk(record.risk),
        },
      });

      this.#pending.delete(operationId);
      this.#committed.set(operationId, record);
      return publicCommitRecord(record);
    } catch (error) {
      if (mutationApplied) {
        try {
          this.#restorePreCommitState({
            absolutePath,
            existedBefore: proposal.existedBefore,
            beforeBuffer: current,
            expectedCurrentSha: proposal.sha256After,
          });
          const restored = readBufferOrNull(absolutePath);
          const restoredSha = restored === null ? null : sha256(restored);
          if (restoredSha !== proposal.sha256Before) {
            fail('COMMIT_RECOVERY_VERIFY_FAILED', 'Failed to verify recovery after unsuccessful commit');
          }
        } catch (recoveryError) {
          fail('COMMIT_RECOVERY_FAILED', 'Commit failed and automatic recovery also failed', {
            commitError: serializeError(error),
            recoveryError: serializeError(recoveryError),
          });
        }
      }
      if (snapshotPath) {
        bestEffortSafeRemove({ root: this.#root, filePath: snapshotPath, pathOptions: this.#pathOptions });
      }
      throw error;
    }
  }

  rollback(operationId, { confirmedPath = null } = {}) {
    const record = this.#committed.get(operationId);
    if (!record) fail('ROLLBACK_UNKNOWN_OPERATION', 'No committed operation with that id');
    if (!this.#confirmationMatches(confirmedPath, record.absolutePath)) {
      fail('APPROVAL_REQUIRED', 'Rollback requires confirmation of the exact committed target', {
        expectedPath: record.approvalPath,
      });
    }

    const absolutePath = this.#resolveTarget(record.approvalPath);
    const current = readBufferOrNull(absolutePath);
    const currentSha = current === null ? null : sha256(current);
    if (currentSha !== record.sha256After) {
      fail('ROLLBACK_CONFLICT', 'File changed after commit; refusing rollback', {
        expectedSha256: record.sha256After,
        actualSha256: currentSha,
      });
    }

    let restoreBuffer = null;
    if (record.existedBefore) {
      if (!record.snapshotPath || !fs.existsSync(record.snapshotPath)) {
        fail('SNAPSHOT_MISSING', 'Rollback snapshot is missing');
      }
      const safeSnapshot = resolveSafePath({
        root: this.#root,
        inputPath: record.snapshotPath,
        denySecretLikeNames: false,
        ...this.#pathOptions,
      });
      restoreBuffer = fs.readFileSync(safeSnapshot);
      const snapshotSha = sha256(restoreBuffer);
      if (snapshotSha !== record.snapshotSha256 || snapshotSha !== record.sha256Before) {
        fail('SNAPSHOT_INTEGRITY_FAILED', 'Rollback snapshot failed integrity verification');
      }
    }

    let rollbackApplied = false;
    try {
      if (record.existedBefore) {
        atomicWrite({
          root: this.#root,
          filePath: absolutePath,
          buffer: restoreBuffer,
          pathOptions: this.#pathOptions,
          newFileMode: this.#newFileMode,
          expectedCurrentSha: record.sha256After,
          conflictCode: 'ROLLBACK_CONFLICT',
        });
      } else {
        const target = this.#resolveTarget(record.approvalPath);
        const live = readBufferOrNull(target);
        const liveSha = live === null ? null : sha256(live);
        if (liveSha !== record.sha256After) {
          fail('ROLLBACK_CONFLICT', 'File changed during the rollback window', {
            expectedSha256: record.sha256After,
            actualSha256: liveSha,
          });
        }
        fs.rmSync(target, { force: true });
        bestEffortDirectorySync(path.dirname(target));
      }
      rollbackApplied = true;

      const afterRollback = readBufferOrNull(absolutePath);
      const afterRollbackSha = afterRollback === null ? null : sha256(afterRollback);
      if (afterRollbackSha !== record.sha256Before) {
        fail('ROLLBACK_VERIFY_FAILED', 'Rollback readback verification failed');
      }

      const rolledBackAt = nowIso();
      appendAuditStrict({
        root: this.#root,
        auditPath: this.#auditPath,
        pathOptions: this.#pathOptions,
        entry: {
          event: 'rollback',
          operationId,
          path: record.approvalPath,
          rolledBackAt,
          sha256Restored: afterRollbackSha,
        },
      });

      this.#committed.delete(operationId);
      if (record.snapshotPath) {
        bestEffortSafeRemove({ root: this.#root, filePath: record.snapshotPath, pathOptions: this.#pathOptions });
      }
      return {
        operationId,
        path: record.approvalPath,
        rolledBackAt,
        sha256Restored: afterRollbackSha,
      };
    } catch (error) {
      if (rollbackApplied) {
        try {
          atomicWrite({
            root: this.#root,
            filePath: absolutePath,
            buffer: record.contentAfter,
            pathOptions: this.#pathOptions,
            newFileMode: this.#newFileMode,
            expectedCurrentSha: record.sha256Before,
            conflictCode: 'ROLLBACK_RECOVERY_CONFLICT',
          });
          const restoredCommitted = fs.readFileSync(absolutePath);
          if (sha256(restoredCommitted) !== record.sha256After) {
            fail('ROLLBACK_RECOVERY_VERIFY_FAILED', 'Failed to verify recovery after unsuccessful rollback');
          }
        } catch (recoveryError) {
          fail('ROLLBACK_RECOVERY_FAILED', 'Rollback failed and automatic recovery also failed', {
            rollbackError: serializeError(error),
            recoveryError: serializeError(recoveryError),
          });
        }
      }
      throw error;
    }
  }
}

export { sha256 };
