# AgentSafeFS

[![CI](https://github.com/tomaszteee/AgentSafeFS/actions/workflows/ci.yml/badge.svg)](https://github.com/tomaszteee/AgentSafeFS/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](./LICENSE)
![Node.js >=22](https://img.shields.io/badge/Node.js-%3E%3D22-339933?logo=node.js&logoColor=white)
[![Latest release](https://img.shields.io/github/v/release/tomaszteee/AgentSafeFS?display_name=tag)](https://github.com/tomaszteee/AgentSafeFS/releases/latest)

**Guarded filesystem writes for AI agents, coding assistants, MCP tools, and automation.**

AgentSafeFS is a security-focused Node.js library **and standalone CLI** that makes AI-driven file writes explicit, reviewable, conflict-aware, auditable, and rollback-capable. The library has no runtime dependencies.

## Quick Start

Requires Node.js 22+.

```bash
npm install agentsafefs
```

Minimal library example:

```js
import { AgentSafeFS } from 'agentsafefs';

const safeFs = new AgentSafeFS({ root: process.cwd() });
const proposal = safeFs.proposeWrite({ path: 'notes.txt', content: 'hello\n' });
const result = safeFs.commit(proposal.operationId, {
  confirmedPath: proposal.risk.requiresApproval ? proposal.path : null,
});

console.log(result.sha256After);
```

Minimal CLI check after installation:

```bash
npx agentsafefs doctor --root .
```

Standalone Windows/Linux/macOS binaries remain available from [GitHub Releases](https://github.com/tomaszteee/AgentSafeFS/releases/latest).

[CLI](./docs/CLI.md) · [API](./docs/API.md) · [Threat model](./docs/THREAT_MODEL.md) · [Security](./SECURITY.md) · [Code signing policy](./CODE_SIGNING_POLICY.md) · [Privacy](./PRIVACY.md) · [Contributing](./CONTRIBUTING.md) · [Discussions](https://github.com/tomaszteee/AgentSafeFS/discussions)

## Why AgentSafeFS

- **AI-agent filesystem safety** — separates `propose` from `commit` so writes can be inspected and approved.
- **Path traversal defense** — blocks `..`, unsafe absolute paths, symlink/junction escapes, hard-link targets, and common Windows path aliases.
- **Stale-write protection** — hashes targets at proposal time and revalidates before mutation.
- **Safer mutation pipeline** — sibling temp file, `fsync`, atomic rename where the platform permits it, and SHA-256 readback verification.
- **Rollback with integrity checks** — restores only when snapshots and current target state still match expectations.
- **Audit-friendly** — optional fsynced JSONL audit events without file contents or absolute workspace paths.
- **Cross-platform CI** — tested on Windows, Linux, and macOS with Node.js 22 and 24.


AgentSafeFS puts a narrow safety layer between an automated tool and a workspace. A write is split into an inspectable proposal and a separate commit step:

`propose -> approve when required -> revalidate -> write -> verify -> audit -> optional rollback`

The project intentionally does one thing: make individual file writes harder to perform accidentally, stale, or outside an intended workspace.

## Status

`0.2.0` adds a standalone CLI and native release binaries while keeping the security-focused API deliberately small. The API and CLI may still evolve before `1.0.0`.

The npm package is prepared for public distribution under the `agentsafefs` name. GitHub Releases remain the distribution source for standalone binaries; the source repository is Apache-2.0 licensed.

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

## Standalone CLI

AgentSafeFS can be used without installing Node.js. GitHub Releases publish native single-file executables built from the same guarded-write engine:

| Platform | Asset |
| --- | --- |
| Windows x64 | `agentsafefs-windows-x64.exe` |
| Windows ARM64 | `agentsafefs-windows-arm64.exe` |
| Linux x64 | `agentsafefs-linux-x64` |
| Linux ARM64 | `agentsafefs-linux-arm64` |
| macOS Intel | `agentsafefs-macos-x64` |
| macOS Apple Silicon | `agentsafefs-macos-arm64` |

Example on Windows:

```powershell
.\agentsafefs-windows-x64.exe doctor --root C:\workspace
.\agentsafefs-windows-x64.exe plan --root C:\workspace --target notes.txt --text "hello"
.\agentsafefs-windows-x64.exe write --root C:\workspace --target notes.txt --text "hello"
```

Higher-risk writes do not accept a generic `--yes`. They require the exact guarded target through `--approve <path>`. Use `--json` for automation and MCP/tool integration. Configuration files are loaded only when explicitly selected with `--config`, avoiding silent repository-controlled policy changes.

Release assets include SHA-256 checksums, an SPDX SBOM, and GitHub build-provenance attestations. See [docs/CLI.md](./docs/CLI.md) for commands, exit codes, configuration, verification, and platform signing notes.

### Code signing policy

AgentSafeFS is applying to the SignPath Foundation free Open Source code-signing program for Windows Authenticode signing. **Free code signing provided by SignPath.io, certificate by SignPath Foundation** once the application is approved and the signing integration is enabled. Until then, Windows release notes explicitly identify the binaries as unsigned. See [CODE_SIGNING_POLICY.md](./CODE_SIGNING_POLICY.md) and [PRIVACY.md](./PRIVACY.md).

## Extended library example

Requires Node.js 22+.

```bash
npm test
```

```js
import { AgentSafeFS } from 'agentsafefs';

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

Rollback metadata is held in memory, so rollback currently requires the same `AgentSafeFS` instance that performed the commit. Snapshot bytes are stored on disk under the configured snapshot directory. The CLI therefore does not advertise rollback across separate invocations. Long-running integrations should also define their own snapshot-retention and audit-log rotation policy after rollback is no longer required.

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

The suite covers Windows junctions and path aliases, hard links, stale writes, policy/approval behavior, snapshot tampering, rollback conflicts, audit recovery, binary data, CLI approval behavior, JSON output, config handling, and non-mutating plans. CI runs across Windows, Linux, and macOS.

## Security

Please read [SECURITY.md](./SECURITY.md) before reporting a vulnerability.

## Scope

AgentSafeFS is deliberately filesystem-only. See [SCOPE.md](./SCOPE.md).

## License

Apache License 2.0. See [LICENSE](./LICENSE).
