# Security Policy

AgentSafeFS is security-sensitive software. Reports that involve filesystem escape, stale overwrite, approval bypass, rollback corruption, snapshot tampering, or sensitive path exposure should not be filed as public issues before maintainers have had a chance to investigate.

## Supported versions

Security fixes currently target the latest `0.2.x` release line.

## Reporting a vulnerability

Prefer GitHub private vulnerability reporting when it is enabled for the repository. Otherwise contact the repository maintainers privately before public disclosure.

A useful report includes:

- affected version or commit,
- operating system, filesystem, and Node.js version,
- a minimal reproduction,
- expected and actual behavior,
- whether the issue crosses the configured root, bypasses approval/policy, defeats stale-write detection, modifies data before a failure is returned, or exposes sensitive paths.

## Security invariants

A regression includes behavior where AgentSafeFS:

- resolves a guarded write outside the configured root,
- follows a symlink/junction in a guarded target path,
- writes through an existing hard-linked target,
- permits Windows path aliases to bypass the root or policy checks,
- commits after the target hash changed since proposal,
- commits an approval-required operation without confirmation of the same canonical target,
- lets mutations of a returned proposal or constructor input rewrite internal operation state,
- silently commits the same pending operation twice,
- rolls back over data changed after the original commit,
- applies a rollback snapshot before verifying its integrity,
- reports a successful commit without readback verification,
- returns an audit/verification failure after mutation without first attempting verified recovery,
- recovery overwrites or deletes a target that changed again after the failed mutation/rollback,
- the CLI auto-loads repository-controlled configuration without an explicit `--config`,
- the CLI permits an approval-required write through a generic yes/no flag instead of exact-target confirmation.

## Out of scope

AgentSafeFS is not designed to defend against:

- code that has direct filesystem access and intentionally bypasses the library,
- a hostile independent local process winning a narrow TOCTOU race between the final path validation and filesystem rename,
- compromised operating-system or filesystem implementations,
- malware execution, process isolation, network isolation, or privilege escalation,
- cryptographic tampering of the audit log (the JSONL audit is not a signed ledger).

See [docs/THREAT_MODEL.md](./docs/THREAT_MODEL.md) for the full boundary.
