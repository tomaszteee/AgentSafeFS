# Threat Model

AgentSafeFS protects a cooperating application from common filesystem mistakes and stale automation. It is not an operating-system security boundary.

## Assets

The primary assets are:

- files inside the configured workspace,
- files outside the configured workspace that must not be modified through AgentSafeFS,
- pre-write bytes needed for rollback,
- approval intent associated with one concrete target,
- audit records that describe successful mutations and rollbacks.

## Trusted components

AgentSafeFS assumes:

- the Node.js runtime and operating system are not compromised,
- the process using AgentSafeFS has legitimate access to the configured root,
- callers use AgentSafeFS for the writes they want guarded,
- cryptographic SHA-256 behaves as expected.

## Defended scenarios

### Path escape

The library rejects lexical traversal, absolute paths outside root, symlinks/junctions in the guarded path, and existing hard-linked targets. On Windows it also rejects NTFS alternate data streams, device namespace paths, reserved device names, and trailing dot/space aliases. Existing path prefixes are canonicalized after link checks so NTFS 8.3 short-name aliases cannot bypass policy, approval, secret-name, or reserved-internal-path comparisons.

Each commit revalidates the target path instead of trusting the path result cached at proposal time. Missing parent directories are created only between validations, followed by another validation before rename.

### Stale writes

The file's SHA-256 hash (or non-existence) is captured at proposal time and compared again immediately before mutation. If the bytes changed, the commit fails.

This is stale-write detection, not a kernel-level atomic compare-and-swap. Two independent hostile processes can still race the tiny interval between the final check and rename.

### Approval confusion

Approval-required writes accept a `confirmedPath` only when it resolves to the same canonical target as the proposal. Windows approval comparison is case-insensitive because the filesystem namespace is case-insensitive. POSIX approval comparison is exact-case even when risk-policy matching is configured case-insensitively, preventing two distinct case-sensitive files from sharing one approval.

### Mutable application objects

Returned proposal/result objects are copies. Operation records, root, policy, path options, snapshots, and committed state are held in JavaScript private fields. Caller-owned policy arrays/Sets and input buffers are copied when accepted.

### Snapshot tampering

Rollback snapshots are read only after path validation and SHA-256 integrity verification. Missing, modified, symlinked/junctioned, or hard-linked snapshots cause rollback to fail before target bytes are replaced.

### Failure after mutation

A commit uses a temporary sibling file, fsync, rename, and readback verification. If readback or configured audit persistence fails after mutation, AgentSafeFS attempts to restore the pre-commit bytes (or remove a newly created file) and verifies recovery before returning the original failure.

Recovery itself is guarded by the hash of the state AgentSafeFS expects to be recovering from. If another actor changes or replaces the target after the original mutation, recovery fails closed rather than overwriting or deleting that newer data.

Rollback uses the inverse pattern: if a failure happens after rollback mutation, it attempts to restore and verify the committed bytes, again only while the target still matches the expected post-rollback state.

## Explicitly out of scope

### Direct bypass

If code has filesystem permissions and directly calls `fs.writeFile`, shell commands, native APIs, or another library, AgentSafeFS cannot stop it. Put OS permissions and process isolation around untrusted code.

### Hostile concurrent local process / TOCTOU

Portable Node.js does not expose a cross-platform directory-handle/openat transaction API that would make every path-component validation and final rename one indivisible kernel operation. AgentSafeFS narrows the race window with repeated checks but does not claim protection against a hostile process intentionally swapping directory structure at the final instant.

### Full metadata rollback

Snapshots preserve prior file bytes and the write path preserves existing POSIX mode bits. Rollback does not promise restoration of all ACLs, xattrs, ownership metadata, timestamps, alternate streams, or filesystem-specific metadata.

### Audit transaction coupling and tamper evidence

Audit entries are fsynced JSONL, but the audit file and target file are not one atomic filesystem transaction. A crash or low-level I/O failure during the final audit append can leave a partial trailing line or, in an uncertain fsync/close outcome, an event for a mutation that AgentSafeFS subsequently recovered. Consumers that require authoritative accounting should reconcile audit events with target state and operation results.

The log is also not signed or hash-chained. A separate process with write permission can alter historical audit data.

### Persistence across process restart

Pending and committed operation metadata is intentionally in memory in `0.1.x`. A new process cannot roll back a previous process's operation merely because snapshot bytes remain on disk. Committed records retain post-commit bytes in memory so rollback recovery can restore them; large or numerous outstanding committed operations therefore consume memory. Committed snapshots are not automatically pruned, and audit logs are not automatically rotated; integrations are responsible for retention once rollback/history is no longer required.

### Availability attacks

A caller or local process with filesystem access can fill the disk, lock files, change permissions, remove snapshots, or otherwise cause operations to fail. AgentSafeFS aims to fail closed, not guarantee availability.

## Security posture

When a behavior is ambiguous, AgentSafeFS prefers refusal over following aliases or guessing intent. Hard-link denial is intentionally fail-closed across both the transaction class and the exported path resolver.
