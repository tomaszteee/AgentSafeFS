# Contributing

Thanks for helping improve AgentSafeFS.

Because this package sits on a filesystem mutation boundary, changes that appear small can have security consequences. Please keep contributions narrow and testable.

## Development

Requirements:

- Node.js 22+
- Git

Run the checks before opening a pull request:

```bash
npm run check
npm test
```

## Security-sensitive changes

Changes to path resolution, approval binding, snapshots, rollback, audit behavior, Windows path handling, or stale-write detection should include a regression test that demonstrates the unsafe behavior before the fix and the expected refusal after the fix.

Prefer fail-closed behavior. If an operation has already mutated a target before a later step fails, recovery behavior must be explicit and tested.

## Scope

Please read [SCOPE.md](./SCOPE.md). Higher-level agent orchestration, scheduling, model integration, and unrelated automation features are intentionally outside this package.

## Pull requests

A focused pull request should include:

- a clear description of the behavior being changed,
- tests for new or corrected behavior,
- documentation updates when the public contract changes,
- no secrets, local machine paths, generated state, or unrelated refactors.

Security vulnerabilities should follow [SECURITY.md](./SECURITY.md), not the public issue tracker.
