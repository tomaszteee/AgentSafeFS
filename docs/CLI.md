# AgentSafeFS CLI

AgentSafeFS 0.2.x includes a command-line interface and standalone executables for guarded filesystem writes.

The CLI is intentionally narrow: it plans or commits one file write at a time using the same path, policy, stale-write, verification, audit, and snapshot protections as the library API.

## Commands

```text
agentsafefs plan  --target <path> (--from <file> | --text <text> | --stdin) [options]
agentsafefs write --target <path> (--from <file> | --text <text> | --stdin) [options]
agentsafefs doctor [options]
agentsafefs --version
```

`plan` never mutates the target. `write` performs `propose -> approval when required -> revalidate -> write -> verify -> audit` in one process.

## Exact-target approval

Higher-risk writes fail closed unless the exact target is confirmed:

```powershell
.\agentsafefs-windows-x64.exe write --root C:\workspace --target scripts\deploy.ps1 --from .\deploy.ps1
```

The command returns `APPROVAL_REQUIRED` and shows the expected target. Re-run with the same target:

```powershell
.\agentsafefs-windows-x64.exe write --root C:\workspace --target scripts\deploy.ps1 --from .\deploy.ps1 --approve scripts\deploy.ps1
```

Approval is resolved through AgentSafeFS path validation; a free-form yes/no flag is deliberately not accepted.

## Configuration

Configuration is **never auto-loaded** from the current directory. Pass `--config <file>` explicitly, or use `--root <dir>` with the built-in defaults. This avoids a repository-controlled config silently widening the CLI root or weakening policy.

Example:

```json
{
  "root": ".",
  "auditPath": ".agentsafefs/audit.jsonl",
  "snapshotDir": ".agentsafefs/snapshots",
  "operationTtlMs": 300000,
  "policy": {
    "immutable": ["vendor"],
    "protectedPaths": ["config"],
    "sensitiveAreas": ["infra"]
  }
}
```

Relative `root` values are resolved from the configuration file directory. Target paths remain guarded by the configured root.

For sensitive payloads, prefer `--stdin` or `--from` over `--text`, because command-line text may be retained in shell history. `--from` reads the source file with the current process permissions; AgentSafeFS remains a guarded **write** layer, not a read sandbox.

## Machine-readable output

Add `--json` to `plan`, `write`, or `doctor`. Success is written to stdout; errors are written to stderr.

Exit codes:

| Code | Meaning |
| ---: | --- |
| 0 | Success |
| 1 | Unexpected/internal error |
| 2 | Usage, input, root, or configuration error |
| 3 | Policy or path-safety denial |
| 4 | Exact-target approval required |
| 5 | Conflict, integrity, recovery, or verification failure |

## Standalone downloads

GitHub Releases publish native executables that embed Node.js; users do not need Node.js installed.

- `agentsafefs-windows-x64.exe`
- `agentsafefs-windows-arm64.exe`
- `agentsafefs-linux-x64`
- `agentsafefs-linux-arm64`
- `agentsafefs-macos-x64`
- `agentsafefs-macos-arm64`

Release assets also include `SHA256SUMS.txt`, an SPDX SBOM, and GitHub artifact attestations for build provenance.

Verify provenance with GitHub CLI:

```bash
gh attestation verify ./agentsafefs-linux-x64 -R tomaszteee/AgentSafeFS
```

### Signing status

Windows executables are currently unsigned because the project does not yet have an Authenticode code-signing certificate. Windows SmartScreen may therefore warn on first use.

macOS executables are ad-hoc signed in CI so the injected SEA binary has a valid local code signature, but they are not Apple Developer ID signed or notarized.

Always verify the SHA-256 checksum and, when possible, the GitHub build-provenance attestation before running a downloaded binary.

## Rollback boundary

The library's rollback metadata is held in memory. A standalone CLI process exits after each command, so the CLI does **not** advertise cross-invocation rollback. Integrations that require same-process rollback should use the JavaScript API directly.
