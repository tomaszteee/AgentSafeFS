# Project Scope

AgentSafeFS is intentionally narrow: it is a filesystem-safety library, not an agent platform.

## In scope

- root-scoped path safety,
- symlink/junction and hard-link defenses,
- risk classification,
- proposal-before-mutation,
- approval bound to the target path,
- stale-write detection,
- snapshots,
- atomic replacement,
- readback verification,
- rollback,
- audit logging,
- filesystem-specific security tests.

## Non-goals

AgentSafeFS does not provide:

- an agent runtime,
- task routing or scheduling,
- persistent conversation or application state,
- workflow recovery/orchestration,
- model/provider integration,
- browser or shell automation,
- an operating-system sandbox.

Keeping these boundaries explicit makes the package easier to audit and lets higher-level systems integrate it without coupling their architecture to the filesystem safety layer.
