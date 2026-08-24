import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { execFileSync } from 'node:child_process';
import { build } from 'esbuild';

const SENTINEL = 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2';
const names = {
  win32: 'windows',
  linux: 'linux',
  darwin: 'macos',
};

if (!names[process.platform]) throw new Error(`Unsupported SEA build platform: ${process.platform}`);
if (!['x64', 'arm64'].includes(process.arch)) throw new Error(`Unsupported SEA build architecture: ${process.arch}`);

const root = path.resolve(import.meta.dirname, '..');
const dist = path.join(root, 'dist');
const work = path.join(dist, '.sea-work');
fs.rmSync(work, { recursive: true, force: true });
fs.mkdirSync(work, { recursive: true });
fs.mkdirSync(dist, { recursive: true });

const bundle = path.join(work, 'agentsafefs-cli.cjs');
await build({
  entryPoints: [path.join(root, 'src', 'cli.mjs')],
  bundle: true,
  platform: 'node',
  format: 'cjs',
  target: 'node22',
  outfile: bundle,
  sourcemap: false,
  legalComments: 'none',
});

const blob = path.join(work, 'sea-prep.blob');
const seaConfig = path.join(work, 'sea-config.json');
fs.writeFileSync(seaConfig, JSON.stringify({
  main: bundle,
  output: blob,
  disableExperimentalSEAWarning: true,
  useSnapshot: false,
  useCodeCache: false,
  execArgvExtension: 'none',
}, null, 2));

execFileSync(process.execPath, ['--experimental-sea-config', seaConfig], { cwd: root, stdio: 'inherit' });

const suffix = process.platform === 'win32' ? '.exe' : '';
const outputName = `agentsafefs-${names[process.platform]}-${process.arch}${suffix}`;
const outputPath = path.join(dist, outputName);
fs.copyFileSync(process.execPath, outputPath);

if (process.platform === 'win32') {
  try {
    const found = execFileSync('where.exe', ['signtool.exe'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })
      .split(/\r?\n/)
      .find(Boolean);
    if (found) execFileSync(found, ['remove', '/s', outputPath], { stdio: 'inherit' });
  } catch {
    // Node documents signature removal as optional on Windows. postject may warn when it is skipped.
  }
}

if (process.platform === 'darwin') {
  try {
    execFileSync('codesign', ['--remove-signature', outputPath], { stdio: 'inherit' });
  } catch {
    // A runner-provided Node binary may already be unsigned; injection can proceed.
  }
}

const postjectCli = path.join(root, 'node_modules', 'postject', 'dist', 'cli.js');
const postjectArgs = [postjectCli, outputPath, 'NODE_SEA_BLOB', blob, '--sentinel-fuse', SENTINEL];
if (process.platform === 'darwin') postjectArgs.push('--macho-segment-name', 'NODE_SEA');
execFileSync(process.execPath, postjectArgs, { cwd: root, stdio: 'inherit' });

if (process.platform === 'darwin') {
  execFileSync('codesign', ['--force', '--sign', '-', outputPath], { stdio: 'inherit' });
}
if (process.platform !== 'win32') fs.chmodSync(outputPath, 0o755);

const version = execFileSync(outputPath, ['--version'], { encoding: 'utf8' }).trim();
if (version !== '0.2.0') throw new Error(`Standalone binary version mismatch: ${version}`);
execFileSync(outputPath, ['doctor', '--root', os.tmpdir(), '--json'], { stdio: 'pipe' });

fs.rmSync(work, { recursive: true, force: true });
process.stdout.write(`${outputPath}\n`);
