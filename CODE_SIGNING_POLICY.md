# Code signing policy

AgentSafeFS treats release signing as part of the software supply-chain security boundary. This policy applies to official downloadable executables published from this repository.

## SignPath Foundation status

AgentSafeFS is applying to the SignPath Foundation Open Source code-signing program. Until that application is approved and the repository signing integration is enabled, Windows release binaries are explicitly described as unsigned.

Once approved, the Windows release process will use:

**Free code signing provided by SignPath.io, certificate by SignPath Foundation.**

No paid code-signing certificate is required by this project policy.

## Scope of signed artifacts

Only official AgentSafeFS Windows executables built by GitHub Actions from this repository may be submitted for SignPath signing:

- `agentsafefs-windows-x64.exe`
- `agentsafefs-windows-arm64.exe`

The source, build scripts, dependency lockfile, and release workflow are all version-controlled in this repository. Official release builds use GitHub-hosted runners. An unsigned artifact is uploaded to GitHub Actions before any SignPath signing request so SignPath can verify build origin.

Linux release binaries are authenticated with SHA-256 checksums and GitHub build-provenance attestations. macOS release binaries are ad-hoc signed by CI and additionally covered by SHA-256 checksums and GitHub build-provenance attestations; Apple Developer ID notarization is not claimed.

## Project roles

AgentSafeFS is currently maintained by a single project owner.

- **Authors / committers:** [@tomaszteee](https://github.com/tomaszteee)
- **Reviewer for external contributions:** [@tomaszteee](https://github.com/tomaszteee)
- **Code-signing approver:** [@tomaszteee](https://github.com/tomaszteee)

Changes proposed by external contributors must be reviewed by the maintainer before merge. Maintainer-authored changes may be committed directly in the author/committer role. Every SignPath Foundation release-signing request requires manual approval by the code-signing approver.

## Release and origin rules

Official releases follow these rules:

1. The package version and release tag must match.
2. CI must pass before a release tag is created.
3. Native executables are built on GitHub-hosted runners from repository-controlled workflows.
4. Release actions are pinned to immutable commit SHAs where practical.
5. Windows PE metadata identifies the product as `AgentSafeFS` and carries the package version before signing.
6. A Windows artifact is uploaded to GitHub Actions before it is submitted to SignPath.
7. SignPath signing is fail-closed: when signing is enabled, a failed or invalid signing result prevents publication.
8. Final release assets receive SHA-256 checksums and GitHub build-provenance attestations.
9. Published release tags are treated as immutable. A corrected build receives a new version/tag rather than rewriting an existing release tag.

## Privacy

See [PRIVACY.md](./PRIVACY.md).

The standalone AgentSafeFS CLI has no telemetry, advertising, analytics, automatic update checks, or background network communication. In the terminology requested by the SignPath Foundation policy:

> This program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it.

The AgentSafeFS library can be embedded in other software; network behavior of a host application is outside AgentSafeFS and must be documented by that host application.

## Verification

For every official release, users should verify `SHA256SUMS.txt` and may verify GitHub build provenance. After SignPath Foundation enrollment is active, Windows users may additionally inspect the Authenticode signature and confirm that it is valid and chains to the SignPath Foundation signing identity used for the project.

## Incident response and revocation

If signing credentials, release automation, or project control are suspected to be compromised, release signing must stop until the incident is investigated. The maintainer will cooperate with SignPath Foundation on any required certificate suspension or revocation and will publish a new release rather than silently replacing a previously published signed binary.
