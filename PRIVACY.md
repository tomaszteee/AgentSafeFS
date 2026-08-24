# Privacy policy

AgentSafeFS is a local filesystem-safety library and standalone command-line tool.

## Standalone CLI

The standalone AgentSafeFS CLI does not include telemetry, analytics, advertising, automatic update checks, crash-report uploads, or background network communication. It reads local inputs selected by the operator and writes only through the guarded filesystem flow configured by the operator.

**This program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it.**

The CLI may read replacement content from a file explicitly named with `--from`, from `--stdin`, or from `--text`. Those inputs remain local unless the operator independently routes them through a networked program or service.

## Library use

The AgentSafeFS library itself does not send data over the network. Software that embeds AgentSafeFS may have its own network behavior; that behavior is controlled by the host application and is outside this project's privacy contract.

## Build and release infrastructure

GitHub and, once the free OSS signing application is approved, SignPath.io / SignPath Foundation are used by project maintainers to build, attest, distribute, and sign release artifacts. These services are part of the project release process, not runtime telemetry from the AgentSafeFS CLI.

## Data retention

AgentSafeFS may create local snapshots and an optional local JSONL audit log when configured to do so. Their retention is controlled by the operator. AgentSafeFS does not upload these files.

For security reports, see [SECURITY.md](./SECURITY.md).
