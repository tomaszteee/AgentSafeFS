import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const root = path.resolve(import.meta.dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const changelog = fs.readFileSync(path.join(root, 'CHANGELOG.md'), 'utf8');
const marker = `## [${pkg.version}]`;
const start = changelog.indexOf(marker);
if (start === -1) throw new Error(`CHANGELOG.md has no section for ${pkg.version}`);
const remainder = changelog.slice(start);
const next = remainder.slice(marker.length).search(/\n## \[/);
const section = next === -1 ? remainder : remainder.slice(0, marker.length + next);

process.stdout.write(`# AgentSafeFS v${pkg.version}\n\n`);
process.stdout.write('Standalone CLI release for guarded filesystem writes by AI agents, coding assistants, MCP tools, and automation.\n\n');
process.stdout.write(section.replace(/^## \[[^\]]+\][^\n]*\n/, ''));
process.stdout.write('\n## Standalone downloads\n\n');
process.stdout.write('- Windows x64 and ARM64 (`.exe`)\n');
process.stdout.write('- Linux x64 and ARM64\n');
process.stdout.write('- macOS Intel x64 and Apple Silicon ARM64\n');
process.stdout.write('- npm-compatible `.tgz`, SPDX SBOM, and `SHA256SUMS.txt`\n\n');
const signPathEnabled = process.env.SIGNPATH_ENABLED === 'true';
process.stdout.write('\n## Code signing policy\n\n');
process.stdout.write('[Code signing policy](https://github.com/tomaszteee/AgentSafeFS/blob/main/CODE_SIGNING_POLICY.md) · [Privacy policy](https://github.com/tomaszteee/AgentSafeFS/blob/main/PRIVACY.md)\n\n');
if (signPathEnabled) {
  process.stdout.write('Windows binaries in this release are Authenticode-signed through the project SignPath Foundation Open Source signing integration. Free code signing provided by SignPath.io, certificate by SignPath Foundation.\n\n');
} else {
  process.stdout.write('Windows binaries in this release are unsigned while the SignPath Foundation Open Source application/integration is pending. The project policy is to use free code signing provided by SignPath.io, certificate by SignPath Foundation once approved.\n\n');
}
process.stdout.write('macOS binaries are ad-hoc signed by CI but are not Apple-notarized. Verify SHA-256 checksums and GitHub build provenance before running downloaded binaries.\n');
