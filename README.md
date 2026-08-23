# AgentSafeFS

Guarded filesystem writes for AI agents, coding assistants, and automation.

AgentSafeFS puts a narrow safety layer between an automated tool and a workspace. A write is split into an inspectable proposal and a separate commit step:

`propose -> approve when required -> revalidate -> write -> verify -> audit -> optional rollback`

The project intentionally does one thing: make individual file writes harder to perform accidentally, stale, or outside an intended workspace.

## Status

`0.1.0` is an early security-focused release candidate. The API is small on purpose and may still change before `1.0.0`.

The package is marked `private: true` only to prevent accidental npm publication during the initial GitHub release. The source repository itself is licensed under Apache-2.0.

## What it protects against

- `..` traversal and absolute paths outside the configured root
- directory symlink and Windows junction escapes, including through non-existing descendants
- writes through existing hard-linked targets
- common Windows path aliases: NTFS ADS, 8.3 short-name aliases, reserved device names, trailing-dot/space aliases, and device namespaces
- case-variant policy bypasses on Windows
- secret-like filenames such as `.env`, key files, and token/credential-looking names
- stale writes when the target changed after proposal
- unapproved writes to protected paths or script/executable-like extensions
- mutation of returned proposal objects or constructor policy inputs
- repeated commit calls and expired proposals
- rollback over newer third-party data
- corrupted, hard-linked, or replaced rollback snapshots
- audit failures that occur after mutation: recovery is verified and refuses to overwrite a newer third-party change

## Core properties

- Workspace root must already exist and may not itself be a symlink/junction.
- Symlinks/junctions anywhere in a guarded target path are denied rather than followed.
- Existing hard-linked files are always denied.
- `proposeWrite()` never mutates the target.
- Approval is bound to the same canonical target, not merely a free-form acknowledgement. On POSIX, confirmation remains exact-case even when policy matching is configured case-insensitively.
- The target is hashed at proposal time and checked again immediately before mutation.
- Writes use a sibling temporary file, `fsync`, rename, and readback SHA-256 verification.
- Existing POSIX mode bits are preserved. New POSIX files default to `0600` unless `newFileMode` is configured.
- Previous bytes are snapshotted before overwrite and verified by hash before rollback.
- Internal transaction/configuration state uses JavaScript private fields.
- Optional audit events are JSONL and do not include file contents or absolute workspace paths.
- No runtime dependencies.

## Quick start from a clone

Requires Node.js 22+.

```bash
npm test
```

```js
import { AgentSafeFS } from './src/index.mjs';

const safeFs = new AgentSafeFS({
  root: 'C:/workspace',
  auditPath: '.agentsafefs/audit.jsonl',
  policy: {
    immutable: ['vendor'],
    protectedPaths: ['config'],
    sensitiveAreas: ['infra'],
  },
});

const proposal = safeFs.proposeWrite({
  path: 'notes.txt',
  content: 'hello\n',
});

console.log(proposal.risk);

const result = safeFs.commit(proposal.operationId, {
  confirmedPath: proposal.risk.requiresApproval ? proposal.path : null,
});

console.log(result.sha256After);
```

If `notes.txt` changes after `proposeWrite()` and before `commit()`, the commit fails with `CONFLICT_CHANGED_SINCE_PROPOSE` instead of blindly overwriting the newer bytes.

## Approval example

Script/executable-like extensions and configured protected areas are approval-required by default:

```js
const proposal = safeFs.proposeWrite({
  path: 'scripts/deploy.ps1',
  content: '# ...',
});

// Throws APPROVAL_REQUIRED:
safeFs.commit(proposal.operationId);

// Confirmation must resolve to the same target:
safeFs.commit(proposal.operationId, {
  confirmedPath: proposal.path,
});
```

## Rollback

```js
safeFs.rollback(proposal.operationId, {
  confirmedPath: proposal.path,
});
```

Rollback is fail-closed. If the target changed after the commit, or if the snapshot no longer has the expected hash, rollback refuses to overwrite the current data.

Rollback metadata is held in memory, so rollback currently requires the same `AgentSafeFS` instance that performed the commit. Snapshot bytes are stored on disk under the configured snapshot directory. `0.1.x` does not automatically prune committed snapshots or rotate audit logs, so long-running integrations should include their own retention/cleanup policy after rollback is no longer required.

## Important limits

AgentSafeFS is **not** an OS sandbox or permission boundary. Code that can bypass AgentSafeFS and call the filesystem directly still has whatever permissions the operating system gives it.

The library performs repeated path validation to close static and common replacement attacks, but Node.js does not provide a portable `openat`/directory-handle transaction primitive for this design. A hostile independent local process that can rewrite directory structure in the tiny interval between the final validation and rename is outside the current threat model. Recovery paths use their own content-hash checks so a newer third-party change is not intentionally overwritten during recovery. See [docs/THREAT_MODEL.md](./docs/THREAT_MODEL.md).

The audit log is fsynced JSONL, not a cryptographically tamper-evident ledger and not an atomic transaction with the target file; a crash or low-level audit I/O failure can leave a partial/uncertain final audit record. Snapshots preserve file bytes; extended ACLs, xattrs, ownership changes, and timestamps are not a rollback contract.

## API and policy

See [docs/API.md](./docs/API.md).

## Tests

```bash
npm test
```

The suite covers Windows junctions and path aliases, hard links, stale writes, policy/approval behavior, snapshot tampering, rollback conflicts, audit recovery, and binary data. CI runs the suite on Windows, Linux, and macOS.

## Security

Please read [SECURITY.md](./SECURITY.md) before reporting a vulnerability.

## Scope

AgentSafeFS is deliberately filesystem-only. See [SCOPE.md](./SCOPE.md).

## License

Apache License 2.0. See [LICENSE](./LICENSE).
