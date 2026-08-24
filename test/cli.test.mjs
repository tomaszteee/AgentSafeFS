import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const repo = path.resolve(import.meta.dirname, '..');
const cli = path.join(repo, 'src', 'cli.mjs');

function tempRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'agentsafefs-cli-'));
}

function run(args, options = {}) {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd: options.cwd ?? repo,
    input: options.input,
    encoding: 'utf8',
  });
}

function cleanup(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

test('CLI version matches package version', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(repo, 'package.json'), 'utf8'));
  const result = run(['--version']);
  assert.equal(result.status, 0);
  assert.equal(result.stdout.trim(), pkg.version);
});

test('plan is non-mutating and reports LOW risk as JSON', () => {
  const root = tempRoot();
  try {
    const result = run(['plan', '--root', root, '--target', 'notes.txt', '--text', 'hello', '--json']);
    assert.equal(result.status, 0, result.stderr);
    const body = JSON.parse(result.stdout);
    assert.equal(body.ok, true);
    assert.equal(body.action, 'plan');
    assert.equal(body.proposal.path, 'notes.txt');
    assert.equal(body.proposal.risk.level, 'LOW');
    assert.equal(fs.existsSync(path.join(root, 'notes.txt')), false);
  } finally {
    cleanup(root);
  }
});

test('write commits a low-risk text file', () => {
  const root = tempRoot();
  try {
    const result = run(['write', '--root', root, '--target', 'notes.txt', '--text', 'hello']);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(fs.readFileSync(path.join(root, 'notes.txt'), 'utf8'), 'hello');
  } finally {
    cleanup(root);
  }
});

test('write reads bytes from stdin', () => {
  const root = tempRoot();
  try {
    const result = run(['write', '--root', root, '--target', 'stdin.bin', '--stdin', '--json'], { input: 'stdin-data' });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(fs.readFileSync(path.join(root, 'stdin.bin'), 'utf8'), 'stdin-data');
  } finally {
    cleanup(root);
  }
});

test('high-risk extension fails closed without exact approval', () => {
  const root = tempRoot();
  try {
    const result = run(['write', '--root', root, '--target', 'script.ps1', '--text', 'Write-Host hi', '--json']);
    assert.equal(result.status, 4);
    const body = JSON.parse(result.stderr);
    assert.equal(body.error.code, 'APPROVAL_REQUIRED');
    assert.equal(fs.existsSync(path.join(root, 'script.ps1')), false);
  } finally {
    cleanup(root);
  }
});

test('high-risk extension commits with exact approval', () => {
  const root = tempRoot();
  try {
    const result = run(['write', '--root', root, '--target', 'script.ps1', '--text', 'Write-Host hi', '--approve', 'script.ps1']);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(fs.readFileSync(path.join(root, 'script.ps1'), 'utf8'), 'Write-Host hi');
  } finally {
    cleanup(root);
  }
});

test('mismatched approval does not write', () => {
  const root = tempRoot();
  try {
    const result = run(['write', '--root', root, '--target', 'script.ps1', '--text', 'x', '--approve', 'other.ps1']);
    assert.equal(result.status, 4);
    assert.equal(fs.existsSync(path.join(root, 'script.ps1')), false);
  } finally {
    cleanup(root);
  }
});

test('config can deny immutable paths', () => {
  const root = tempRoot();
  try {
    fs.writeFileSync(path.join(root, 'agentsafefs.config.json'), JSON.stringify({
      root: '.',
      policy: { immutable: ['vendor'] },
    }));
    fs.mkdirSync(path.join(root, 'vendor'));
    const result = run(['plan', '--config', 'agentsafefs.config.json', '--target', 'vendor/file.txt', '--text', 'x', '--json'], { cwd: root });
    assert.equal(result.status, 3);
    const body = JSON.parse(result.stderr);
    assert.equal(body.error.code, 'POLICY_DENIED');
  } finally {
    cleanup(root);
  }
});

test('doctor validates a root without mutating it', () => {
  const root = tempRoot();
  try {
    const before = fs.readdirSync(root);
    const result = run(['doctor', '--root', root, '--json']);
    assert.equal(result.status, 0, result.stderr);
    const body = JSON.parse(result.stdout);
    assert.equal(body.ok, true);
    assert.equal(body.action, 'doctor');
    assert.equal(body.standalone, false);
    assert.deepEqual(fs.readdirSync(root), before);
  } finally {
    cleanup(root);
  }
});

test('CLI rejects ambiguous content sources', () => {
  const root = tempRoot();
  try {
    const result = run(['plan', '--root', root, '--target', 'x.txt', '--text', 'x', '--stdin']);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /Exactly one content source/);
  } finally {
    cleanup(root);
  }
});

test('configuration is not auto-loaded from cwd', () => {
  const root = tempRoot();
  try {
    fs.writeFileSync(path.join(root, 'agentsafefs.config.json'), JSON.stringify({
      root: '.',
      policy: { immutable: ['blocked'] },
    }));
    fs.mkdirSync(path.join(root, 'blocked'));
    const result = run(['plan', '--target', 'blocked/file.txt', '--text', 'x', '--json'], { cwd: root });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).proposal.risk.level, 'LOW');
  } finally {
    cleanup(root);
  }
});

test('plan rejects write-only approval option', () => {
  const root = tempRoot();
  try {
    const result = run(['plan', '--root', root, '--target', 'x.txt', '--text', 'x', '--approve', 'x.txt']);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /Option not valid for plan/);
  } finally {
    cleanup(root);
  }
});

test('--from preserves binary bytes exactly', () => {
  const root = tempRoot();
  const sourceDir = tempRoot();
  try {
    const bytes = Buffer.from([0, 1, 2, 127, 128, 254, 255]);
    const source = path.join(sourceDir, 'payload.bin');
    fs.writeFileSync(source, bytes);
    const result = run(['write', '--root', root, '--target', 'payload.bin', '--from', source]);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(fs.readFileSync(path.join(root, 'payload.bin')), bytes);
  } finally {
    cleanup(root);
    cleanup(sourceDir);
  }
});

test('path traversal is denied by the guarded target boundary', () => {
  const base = tempRoot();
  const root = path.join(base, 'root');
  fs.mkdirSync(root);
  try {
    const result = run(['plan', '--root', root, '--target', '../escape.txt', '--text', 'x', '--json']);
    assert.equal(result.status, 3);
    const body = JSON.parse(result.stderr);
    assert.match(body.error.code, /^PATH_/);
    assert.equal(fs.existsSync(path.join(base, 'escape.txt')), false);
  } finally {
    cleanup(base);
  }
});

test('unknown configuration keys fail closed', () => {
  const root = tempRoot();
  try {
    const config = path.join(root, 'bad.json');
    fs.writeFileSync(config, JSON.stringify({ root: '.', unexpected: true }));
    const result = run(['doctor', '--config', config, '--json'], { cwd: root });
    assert.equal(result.status, 2);
    const body = JSON.parse(result.stderr);
    assert.equal(body.error.code, 'CLI_CONFIG_INVALID');
  } finally {
    cleanup(root);
  }
});

test('relative config root resolves from config directory', () => {
  const base = tempRoot();
  try {
    const configDir = path.join(base, 'config');
    const workspace = path.join(base, 'workspace');
    fs.mkdirSync(configDir);
    fs.mkdirSync(workspace);
    const config = path.join(configDir, 'agentsafefs.json');
    fs.writeFileSync(config, JSON.stringify({ root: '../workspace' }));
    const result = run(['doctor', '--config', config, '--json'], { cwd: base });
    assert.equal(result.status, 0, result.stderr);
    const body = JSON.parse(result.stdout);
    assert.equal(path.resolve(body.root), path.resolve(workspace));
  } finally {
    cleanup(base);
  }
});

test('usage errors stay machine-readable when --json is present', () => {
  const result = run(['plan', '--json', '--unknown']);
  assert.equal(result.status, 2);
  const body = JSON.parse(result.stderr);
  assert.equal(body.ok, false);
  assert.equal(body.error.code, 'CLI_USAGE');
});
