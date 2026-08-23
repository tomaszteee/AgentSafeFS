# Changelog

All notable changes to AgentSafeFS will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project intends to use Semantic Versioning.

## [0.1.0] - 2026-08-23

### Added

- root-scoped guarded writes with `proposeWrite()` and `commit()`,
- risk levels and exact-target approval,
- stale-write SHA-256 detection,
- symlink/junction and hard-link defenses,
- Windows ADS/device/namespace/path-alias hardening, including NTFS 8.3 short-name canonicalization,
- snapshots and verified rollback,
- atomic sibling-temp writes with fsync and readback verification,
- verified compare-and-swap recovery when audit/verification fails after mutation,
- protected internal audit/snapshot path topology and partial-snapshot cleanup,
- strict POSIX root containment independent of policy case matching,
- optional JSONL audit log,
- operation TTL and double-commit protection,
- private internal transaction/configuration state,
- TypeScript declarations,
- cross-platform CI configuration and security regression tests,
- public API, scope, threat-model, contribution, and security documentation.
