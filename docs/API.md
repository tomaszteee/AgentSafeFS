# API

## `new AgentSafeFS(options)`

Creates a guarded filesystem writer for one existing workspace root.

### Options

- `root` **required** — existing directory that bounds all guarded targets. The root itself may not be a symlink/junction.
- `policy` — risk policy object.
  - `immutable: string[]` — denied root-relative path prefixes.
  - `protectedPaths: string[]` — root-relative HIGH-risk path prefixes requiring approval.
  - `sensitiveAreas: string[]` — root-relative HIGH-risk path prefixes requiring approval.
  - `highRiskExtensions: Set<string> | string[]` — extensions treated as HIGH risk.
  - `mediumDiffBytes: number` — operations where `max(bytesBefore, bytesAfter)` reaches this threshold become MEDIUM risk and require approval. This is a conservative size threshold, not a byte-diff algorithm. Default: `16384`.
  - `caseSensitive: boolean` — risk-policy and reserved-path comparison mode. Windows and macOS always use conservative case-insensitive policy comparisons and reject `true`; this avoids a policy bypass when the underlying volume is case-insensitive. Other platforms default to case-sensitive and may explicitly use `false`. Root containment itself always follows host path semantics, and approval confirmation remains exact-case on POSIX.
- `operationTtlMs` — pending proposal lifetime. Default: five minutes.
- `auditPath` — optional JSONL audit path inside `root`.
- `snapshotDir` — snapshot directory inside `root`. Default: `.agentsafefs/snapshots`.
- `newFileMode` — POSIX mode for newly created files. Default: `0o600`.
- `clock` — injectable millisecond clock used by tests/advanced integrations.

Configuration that affects safety is copied into private state during construction; later mutation of the caller's arrays/Sets does not weaken the instance. Unknown constructor or policy keys are rejected so configuration typos fail closed. Policy prefixes must be non-empty relative paths; absolute, root-like, NUL-containing, or traversal prefixes are rejected instead of silently failing to match.

## `proposeWrite({ path, content })`

Validates a target and creates an in-memory pending write without mutating the target.

`content` may be a UTF-8 string or any `Uint8Array` (including Node.js `Buffer`). Binary input is copied at proposal time.

Returns:

```js
{
  operationId,
  operation: 'write',
  path,              // canonical root-relative approval path, using '/'
  expiresAtMs,
  sha256Before,      // null if target did not exist
  sha256After,
  bytesBefore,
  bytesAfter,
  existedBefore,
  risk: {
    level,            // LOW | MEDIUM | HIGH
    reason,
    requiresApproval
  }
}
```

A `DENY` policy result throws instead of returning a proposal.

## `commit(operationId, { confirmedPath? })`

Revalidates the path and current bytes, then applies the pending write.

For MEDIUM/HIGH risk operations, `confirmedPath` must resolve to the same canonical target as the proposal.

The commit fails if:

- the operation is unknown/already committed,
- the TTL expired,
- approval is missing or points at a different target,
- the target changed since proposal,
- path safety fails during revalidation,
- snapshot creation fails,
- atomic replacement fails,
- readback SHA-256 verification fails,
- configured audit persistence fails.

If failure occurs after the target mutation was applied, AgentSafeFS attempts to restore and verify the pre-commit state before returning the error. Recovery is compare-and-swap guarded: if another actor changes the target during the recovery window, AgentSafeFS preserves that newer data and throws `COMMIT_RECOVERY_FAILED` instead of overwriting or deleting it.

## `rollback(operationId, { confirmedPath })`

Rolls a committed operation back using its verified snapshot, or removes the target if the committed write originally created a new file.

Rollback always requires confirmation of the same canonical target. It refuses to proceed when:

- the operation is not a committed operation in the current instance,
- the target changed after commit,
- the snapshot is missing,
- the snapshot is now a symlink/junction/hard link,
- the snapshot hash no longer matches the pre-commit hash.

If a failure happens after rollback mutation (for example, an audit I/O failure), AgentSafeFS attempts to restore and verify the committed bytes before returning the error. That recovery is also compare-and-swap guarded and will not overwrite a third-party change made during the recovery window.

After a successful rollback the in-memory committed record is removed and its snapshot file is deleted.

## `resolveSafePath(options)`

Validates one target against an existing root and returns its absolute resolved path. It rejects lexical root escape, symlink/junction path components, existing hard-linked targets, directories when a file target is required, special filesystem objects, common secret-like names, and Windows path aliases/device names.

`allowTargetDirectory: true` is intended for internal directory targets such as snapshot storage; callers should not use it to weaken normal file-write validation. `secretPatterns` may override the default secret-name patterns for standalone use.

Root containment follows host path semantics and is not relaxed by risk-policy case matching.

## `classifyRisk(options)`

Classifies a validated root-relative path as `LOW`, `MEDIUM`, `HIGH`, or `DENY`. Supported operations are `write`, `delete`, and `move`. Invalid paths, operations, sizes, policy shapes, or unknown option names fail closed with `RISK_INPUT_INVALID`.

`DENY` is returned for immutable prefixes. Protected/sensitive prefixes, delete/move operations, configured high-risk extensions, and sufficiently large changes require approval.

## `sha256(buffer)`

Returns the lowercase hexadecimal SHA-256 digest of a `Uint8Array`/`Buffer`.

## `DEFAULT_HIGH_RISK_EXTENSIONS`

Frozen read-only array containing the default script/executable-like extensions treated as HIGH risk. Supplying `policy.highRiskExtensions` replaces this default set for that instance.

## Errors

All library policy/safety errors are `AgentSafeFSError` instances with:

```js
{
  name: 'AgentSafeFSError',
  code: 'SOME_STABLE_CODE',
  message: 'Human-readable explanation',
  details: null | object
}
```

Common codes include:

- `PATH_OUTSIDE_ROOT`
- `PATH_SYMLINK_ESCAPE`
- `PATH_HARDLINK_DENIED`
- `PATH_SECRET_LIKE`
- `PATH_WINDOWS_ADS`
- `PATH_WINDOWS_DEVICE`
- `PATH_WINDOWS_NAMESPACE`
- `PATH_RESERVED_INTERNAL`
- `POLICY_DENIED`
- `APPROVAL_REQUIRED`
- `CONFLICT_CHANGED_SINCE_PROPOSE`
- `OPERATION_EXPIRED`
- `OPERATION_NOT_PENDING`
- `SNAPSHOT_INTEGRITY_FAILED`
- `ROLLBACK_CONFLICT`
- `RISK_INPUT_INVALID`
- `COMMIT_RECOVERY_FAILED`
- `ROLLBACK_RECOVERY_FAILED`

Native filesystem errors may also surface when the operating system rejects an operation before AgentSafeFS can safely complete it.
