import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  AgentSafeFS,
  AgentSafeFSError,
  DEFAULT_HIGH_RISK_EXTENSIONS,
  classifyRisk,
  resolveSafePath,
} from '../src/index.mjs';

function tempRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'agentsafefs-'));
}

function tempPair() {
  const base = tempRoot();
  const root = path.join(base, 'root');
  const outside = path.join(base, 'outside');
  fs.mkdirSync(root);
  fs.mkdirSync(outside);
  return { base, root, outside };
}

function cleanup(target) {
  fs.rmSync(target, { recursive: true, force: true });
}

function expectCode(fn, code) {
  assert.throws(fn, (error) => error instanceof AgentSafeFSError && error.code === code);
}

function createDirectoryLink(target, linkPath) {
  fs.symlinkSync(target, linkPath, process.platform === 'win32' ? 'junction' : 'dir');
}

test('exported default high-risk extensions cannot be mutated', () => {
  assert.equal(Object.isFrozen(DEFAULT_HIGH_RISK_EXTENSIONS), true);
  assert.throws(() => DEFAULT_HIGH_RISK_EXTENSIONS.push('.unsafe'));
  const risk = classifyRisk({ relativePath: 'script.mjs' });
  assert.equal(risk.level, 'HIGH');
});

test('rejects invalid path resolver inputs with a library error', () => {
  const root = tempRoot();
  expectCode(() => resolveSafePath({ root, inputPath: 123 }), 'PATH_INPUT_INVALID');
  expectCode(() => resolveSafePath({ root, inputPath: 'file.txt', denySecretLikeNames: 'yes' }), 'PATH_INPUT_INVALID');
  expectCode(() => resolveSafePath({ root, inputPath: 'file.txt', allowTargetDirectory: 1 }), 'PATH_INPUT_INVALID');
  expectCode(() => resolveSafePath({ root, inputPath: 'file.txt', secretPatterns: ['secret'] }), 'PATH_INPUT_INVALID');
  cleanup(root);
});

test('rejects a missing root', () => {
  const missing = path.join(os.tmpdir(), `agentsafefs-missing-${Date.now()}-${Math.random()}`);
  expectCode(() => new AgentSafeFS({ root: missing }), 'ROOT_NOT_FOUND');
});

test('rejects a file as root', () => {
  const root = tempRoot();
  const file = path.join(root, 'file.txt');
  fs.writeFileSync(file, 'x');
  expectCode(() => new AgentSafeFS({ root: file }), 'ROOT_NOT_DIRECTORY');
  cleanup(root);
});

test('rejects a symlink or junction as the configured root', () => {
  const { base, root, outside } = tempPair();
  const alias = path.join(base, 'root-alias');
  createDirectoryLink(root, alias);
  expectCode(() => new AgentSafeFS({ root: alias }), 'ROOT_SYMLINK_DENIED');
  cleanup(base);
});

test('blocks relative traversal outside configured root', () => {
  const root = tempRoot();
  expectCode(() => resolveSafePath({ root, inputPath: `..${path.sep}escape.txt` }), 'PATH_OUTSIDE_ROOT');
  cleanup(root);
});

test('blocks absolute paths outside configured root', () => {
  const { base, root, outside } = tempPair();
  expectCode(() => resolveSafePath({ root, inputPath: path.join(outside, 'escape.txt') }), 'PATH_OUTSIDE_ROOT');
  cleanup(base);
});

test('case-insensitive policy matching cannot weaken POSIX root containment', {
  skip: process.platform === 'win32',
}, () => {
  const root = tempRoot();
  const parent = path.dirname(root);
  const name = path.basename(root);
  const index = [...name].findIndex((char) => /[a-z]/i.test(char));
  if (index === -1) {
    cleanup(root);
    return;
  }
  const char = name[index];
  const flipped = char === char.toLowerCase() ? char.toUpperCase() : char.toLowerCase();
  const variantName = name.slice(0, index) + flipped + name.slice(index + 1);
  const caseVariantOutside = path.join(parent, variantName, 'escape.txt');
  expectCode(
    () => resolveSafePath({ root, inputPath: caseVariantOutside, caseSensitive: false }),
    'PATH_OUTSIDE_ROOT',
  );
  cleanup(root);
});

test('blocks secret-like filenames in any segment', () => {
  const root = tempRoot();
  expectCode(() => resolveSafePath({ root, inputPath: '.env' }), 'PATH_SECRET_LIKE');
  expectCode(() => resolveSafePath({ root, inputPath: path.join('nested', 'api-token.txt') }), 'PATH_SECRET_LIKE');
  cleanup(root);
});

test('custom global secret regex remains deterministic across calls', () => {
  const root = tempRoot();
  const secretPatterns = [/private/g];
  expectCode(() => resolveSafePath({ root, inputPath: 'private.txt', secretPatterns }), 'PATH_SECRET_LIKE');
  expectCode(() => resolveSafePath({ root, inputPath: 'private.txt', secretPatterns }), 'PATH_SECRET_LIKE');
  cleanup(root);
});

test('blocks an existing directory symlink or junction escape', () => {
  const { base, root, outside } = tempPair();
  createDirectoryLink(outside, path.join(root, 'link'));
  expectCode(() => resolveSafePath({ root, inputPath: path.join('link', 'file.txt') }), 'PATH_SYMLINK_ESCAPE');
  cleanup(base);
});

test('blocks junction escape through a non-existing descendant', () => {
  const { base, root, outside } = tempPair();
  createDirectoryLink(outside, path.join(root, 'link'));
  const safe = new AgentSafeFS({ root });
  expectCode(
    () => safe.proposeWrite({ path: path.join('link', 'newdir', 'pwn.txt'), content: 'x' }),
    'PATH_SYMLINK_ESCAPE',
  );
  assert.equal(fs.existsSync(path.join(outside, 'newdir', 'pwn.txt')), false);
  cleanup(base);
});

test('blocks symlinks even when they point back inside root', () => {
  const root = tempRoot();
  const real = path.join(root, 'real');
  fs.mkdirSync(real);
  createDirectoryLink(real, path.join(root, 'alias'));
  expectCode(() => resolveSafePath({ root, inputPath: path.join('alias', 'file.txt') }), 'PATH_SYMLINK_ESCAPE');
  cleanup(root);
});

test('blocks existing hard-linked targets by default', () => {
  const { base, root, outside } = tempPair();
  const outsideFile = path.join(outside, 'shared.txt');
  const insideFile = path.join(root, 'shared.txt');
  fs.writeFileSync(outsideFile, 'outside');
  fs.linkSync(outsideFile, insideFile);
  expectCode(() => resolveSafePath({ root, inputPath: 'shared.txt' }), 'PATH_HARDLINK_DENIED');
  cleanup(base);
});

test('rejects a directory as a write target', () => {
  const root = tempRoot();
  fs.mkdirSync(path.join(root, 'dir'));
  expectCode(() => resolveSafePath({ root, inputPath: 'dir' }), 'PATH_TARGET_IS_DIRECTORY');
  cleanup(root);
});

test('rejects POSIX FIFO special files', { skip: process.platform === 'win32' }, (t) => {
  const root = tempRoot();
  const fifo = path.join(root, 'pipe');
  const created = spawnSync('mkfifo', [fifo]);
  if (created.status !== 0) {
    cleanup(root);
    t.skip('mkfifo is unavailable on this runner');
    return;
  }
  expectCode(() => resolveSafePath({ root, inputPath: 'pipe' }), 'PATH_SPECIAL_FILE_DENIED');
  cleanup(root);
});

test('Windows-specific path aliases, namespaces, and device names are denied', { skip: process.platform !== 'win32' }, () => {
  const root = tempRoot();
  expectCode(() => resolveSafePath({ root, inputPath: 'file.txt:stream' }), 'PATH_WINDOWS_ADS');
  expectCode(() => resolveSafePath({ root, inputPath: 'NUL.txt' }), 'PATH_WINDOWS_DEVICE');
  expectCode(() => resolveSafePath({ root, inputPath: 'NUL .txt' }), 'PATH_WINDOWS_DEVICE');
  expectCode(() => resolveSafePath({ root, inputPath: 'COM¹.txt' }), 'PATH_WINDOWS_DEVICE');
  expectCode(() => resolveSafePath({ root, inputPath: 'LPT³.log' }), 'PATH_WINDOWS_DEVICE');
  expectCode(() => resolveSafePath({ root, inputPath: 'CONOUT$' }), 'PATH_WINDOWS_DEVICE');
  expectCode(() => resolveSafePath({ root, inputPath: 'name. ' }), 'PATH_WINDOWS_ALIAS');
  expectCode(() => resolveSafePath({ root, inputPath: '\\\\?\\C:\\temp\\x.txt' }), 'PATH_WINDOWS_NAMESPACE');
  expectCode(() => resolveSafePath({ root, inputPath: '//?/C:/temp/x.txt' }), 'PATH_WINDOWS_NAMESPACE');
  expectCode(() => resolveSafePath({ root, inputPath: '\\\\.\\NUL' }), 'PATH_WINDOWS_NAMESPACE');
  cleanup(root);
});

test('Windows NTFS 8.3 aliases cannot bypass protected path policy', { skip: process.platform !== 'win32' }, (t) => {
  const root = tempRoot();
  const longName = 'ProtectedConfigurationDirectory';
  const longDirectory = path.join(root, longName);
  fs.mkdirSync(longDirectory);
  if (longDirectory.includes(' ')) {
    cleanup(root);
    t.skip('test temp path contains spaces; short-name probe uses an unquoted cmd path');
    return;
  }
  const command = `for %I in (${longDirectory}) do @echo %~sI`;
  const shortResult = spawnSync('cmd.exe', ['/d', '/c', command], { encoding: 'utf8' });
  if (shortResult.status !== 0) {
    cleanup(root);
    t.skip('cmd.exe could not resolve an NTFS short path on this runner');
    return;
  }
  const shortDirectory = shortResult.stdout.trim();
  const shortName = path.basename(shortDirectory);
  if (!shortName || shortName.toLocaleLowerCase('en-US') === longName.toLocaleLowerCase('en-US')) {
    cleanup(root);
    t.skip('8.3 short names are disabled on this volume');
    return;
  }

  const safe = new AgentSafeFS({ root, policy: { protectedPaths: [longName] } });
  const proposal = safe.proposeWrite({ path: path.join(shortName, 'settings.txt'), content: 'x' });
  assert.equal(proposal.path, `${longName}/settings.txt`);
  assert.equal(proposal.risk.level, 'HIGH');
  expectCode(() => safe.commit(proposal.operationId), 'APPROVAL_REQUIRED');
  safe.commit(proposal.operationId, { confirmedPath: proposal.path });
  assert.equal(fs.readFileSync(path.join(longDirectory, 'settings.txt'), 'utf8'), 'x');
  cleanup(root);
});

test('rejects invalid transaction configuration', () => {
  const root = tempRoot();
  expectCode(() => new AgentSafeFS(), 'CONFIG_INVALID');
  expectCode(() => new AgentSafeFS(null), 'CONFIG_INVALID');
  expectCode(() => new AgentSafeFS({ root: 123 }), 'CONFIG_INVALID');
  expectCode(() => new AgentSafeFS({ root, audtiPath: 'audit.jsonl' }), 'CONFIG_INVALID');
  expectCode(() => new AgentSafeFS({ root, policy: null }), 'CONFIG_INVALID');
  expectCode(() => new AgentSafeFS({ root, policy: { protectedPath: ['config'] } }), 'CONFIG_INVALID');
  expectCode(() => new AgentSafeFS({ root, operationTtlMs: 0 }), 'CONFIG_INVALID');
  expectCode(() => new AgentSafeFS({ root, newFileMode: 0o1000 }), 'CONFIG_INVALID');
  expectCode(() => new AgentSafeFS({ root, policy: { protectedPaths: 'config' } }), 'CONFIG_INVALID');
  expectCode(() => new AgentSafeFS({ root, policy: { protectedPaths: ['../config'] } }), 'CONFIG_INVALID');
  expectCode(() => new AgentSafeFS({ root, policy: { protectedPaths: ['config/../safe'] } }), 'CONFIG_INVALID');
  expectCode(() => new AgentSafeFS({ root, policy: { protectedPaths: ['C:/config'] } }), 'CONFIG_INVALID');
  expectCode(() => new AgentSafeFS({ root, policy: { protectedPaths: ['.'] } }), 'CONFIG_INVALID');
  expectCode(() => new AgentSafeFS({ root, policy: { highRiskExtensions: 'mjs' } }), 'CONFIG_INVALID');
  expectCode(() => new AgentSafeFS({ root, snapshotDir: '.' }), 'CONFIG_INVALID');

  fs.writeFileSync(path.join(root, 'snapshot-file'), 'x');
  expectCode(() => new AgentSafeFS({ root, snapshotDir: 'snapshot-file' }), 'CONFIG_INVALID');
  expectCode(
    () => new AgentSafeFS({ root, snapshotDir: 'state/snapshots', auditPath: 'state/snapshots/audit.jsonl' }),
    'CONFIG_INVALID',
  );
  expectCode(
    () => new AgentSafeFS({ root, snapshotDir: 'state/snapshots', auditPath: 'state' }),
    'CONFIG_INVALID',
  );
  cleanup(root);
});

test('propose does not mutate disk', () => {
  const root = tempRoot();
  const safe = new AgentSafeFS({ root });
  safe.proposeWrite({ path: 'notes.txt', content: 'hello' });
  assert.equal(fs.existsSync(path.join(root, 'notes.txt')), false);
  cleanup(root);
});

test('low-risk write commits and verifies', () => {
  const root = tempRoot();
  const safe = new AgentSafeFS({ root });
  const proposal = safe.proposeWrite({ path: 'notes.txt', content: 'hello' });
  assert.equal(proposal.risk.level, 'LOW');
  const result = safe.commit(proposal.operationId);
  assert.equal(fs.readFileSync(path.join(root, 'notes.txt'), 'utf8'), 'hello');
  assert.equal(result.sha256After, proposal.sha256After);
  assert.equal(result.path, 'notes.txt');
  cleanup(root);
});

test('binary content is copied at propose time and cannot be mutated externally', () => {
  const root = tempRoot();
  const safe = new AgentSafeFS({ root });
  const content = new Uint8Array([1, 2, 3]);
  const proposal = safe.proposeWrite({ path: 'data.bin', content });
  content[0] = 9;
  safe.commit(proposal.operationId);
  assert.deepEqual(fs.readFileSync(path.join(root, 'data.bin')), Buffer.from([1, 2, 3]));
  cleanup(root);
});

test('mutating the public proposal cannot redirect the internal operation', () => {
  const { base, root, outside } = tempPair();
  const safe = new AgentSafeFS({ root });
  const proposal = safe.proposeWrite({ path: 'safe.txt', content: 'safe' });
  proposal.path = path.join(outside, 'outside.txt');
  proposal.risk.level = 'HIGH';
  safe.commit(proposal.operationId);
  assert.equal(fs.readFileSync(path.join(root, 'safe.txt'), 'utf8'), 'safe');
  assert.equal(fs.existsSync(path.join(outside, 'outside.txt')), false);
  assert.deepEqual(Object.keys(safe), []);
  assert.equal('pending' in safe, false);
  assert.equal('committed' in safe, false);
  assert.equal('root' in safe, false);
  assert.equal('policy' in safe, false);
  assert.equal('pathOptions' in safe, false);
  cleanup(base);
});

test('mutating constructor policy inputs cannot weaken an existing instance', () => {
  const root = tempRoot();
  const protectedPaths = ['config'];
  const extensions = new Set(['.xyz']);
  const safe = new AgentSafeFS({ root, policy: { protectedPaths, highRiskExtensions: extensions } });
  protectedPaths.length = 0;
  extensions.clear();
  const protectedProposal = safe.proposeWrite({ path: 'config/settings.txt', content: 'x' });
  const extensionProposal = safe.proposeWrite({ path: 'file.xyz', content: 'x' });
  assert.equal(protectedProposal.risk.level, 'HIGH');
  assert.equal(extensionProposal.risk.level, 'HIGH');
  cleanup(root);
});

test('high-risk extension requires confirmation of the same canonical target', () => {
  const root = tempRoot();
  const safe = new AgentSafeFS({ root });
  const proposal = safe.proposeWrite({ path: path.join('scripts', '..', 'script.mjs'), content: 'export default 1;\n' });
  assert.equal(proposal.path, 'script.mjs');
  assert.equal(proposal.risk.level, 'HIGH');
  expectCode(() => safe.commit(proposal.operationId), 'APPROVAL_REQUIRED');
  expectCode(() => safe.commit(proposal.operationId, { confirmedPath: 'other.mjs' }), 'APPROVAL_REQUIRED');
  safe.commit(proposal.operationId, { confirmedPath: 'script.mjs' });
  assert.equal(fs.existsSync(path.join(root, 'script.mjs')), true);
  cleanup(root);
});

test('POSIX approval remains exact-case even with case-insensitive policy matching', {
  skip: process.platform === 'win32',
}, () => {
  const root = tempRoot();
  const safe = new AgentSafeFS({ root, policy: { caseSensitive: false } });
  const proposal = safe.proposeWrite({ path: 'script.mjs', content: 'export default 1;\n' });
  expectCode(
    () => safe.commit(proposal.operationId, { confirmedPath: 'SCRIPT.MJS' }),
    'APPROVAL_REQUIRED',
  );
  safe.commit(proposal.operationId, { confirmedPath: proposal.path });
  cleanup(root);
});

test('protected path matching can be case-insensitive', () => {
  const risk = classifyRisk({
    relativePath: 'CONFIG/settings.txt',
    protectedPaths: ['config'],
    caseSensitive: false,
  });
  assert.equal(risk.level, 'HIGH');
});

test('protected path matching normalizes canonically equivalent Unicode', () => {
  const risk = classifyRisk({
    relativePath: 'cafe\u0301/settings.txt',
    protectedPaths: ['caf\u00e9'],
    caseSensitive: process.platform === 'win32' || process.platform === 'darwin' ? false : true,
  });
  assert.equal(risk.level, 'HIGH');
});

test('custom high-risk extensions are normalized', () => {
  const risk = classifyRisk({ relativePath: 'tool.XYZ', highRiskExtensions: ['XYZ'] });
  assert.equal(risk.level, 'HIGH');
});

test('standalone risk classifier fails closed on invalid inputs', () => {
  expectCode(() => classifyRisk(), 'RISK_INPUT_INVALID');
  expectCode(() => classifyRisk(null), 'RISK_INPUT_INVALID');
  expectCode(() => classifyRisk({ relativePath: 'file.txt', protectedPath: ['config'] }), 'RISK_INPUT_INVALID');
  expectCode(() => classifyRisk({ relativePath: '.' }), 'RISK_INPUT_INVALID');
  expectCode(() => classifyRisk({ relativePath: 'a/..' }), 'RISK_INPUT_INVALID');
  expectCode(() => classifyRisk({ relativePath: 'C:/outside.txt' }), 'RISK_INPUT_INVALID');
  expectCode(() => classifyRisk({ relativePath: '../outside.txt' }), 'RISK_INPUT_INVALID');
  expectCode(() => classifyRisk({ relativePath: 'file.txt', operation: 'unknown' }), 'RISK_INPUT_INVALID');
  expectCode(() => classifyRisk({ relativePath: 'file.txt', protectedPaths: ['../config'] }), 'RISK_INPUT_INVALID');
  expectCode(() => classifyRisk({ relativePath: 'file.txt', protectedPaths: ['C:/config'] }), 'RISK_INPUT_INVALID');
  expectCode(() => classifyRisk({ relativePath: 'file.txt', diffBytes: Number.NaN }), 'RISK_INPUT_INVALID');
  expectCode(() => classifyRisk({ relativePath: 'file.txt', highRiskExtensions: 'mjs' }), 'RISK_INPUT_INVALID');
});

test('Windows and macOS use case-insensitive protected paths', {
  skip: process.platform !== 'win32' && process.platform !== 'darwin',
}, () => {
  const root = tempRoot();
  const safe = new AgentSafeFS({ root, policy: { protectedPaths: ['config'] } });
  const proposal = safe.proposeWrite({ path: path.join('CONFIG', 'settings.txt'), content: 'x' });
  assert.equal(proposal.risk.level, 'HIGH');
  cleanup(root);
});

test('Windows and macOS refuse unsafe caseSensitive=true configuration', {
  skip: process.platform !== 'win32' && process.platform !== 'darwin',
}, () => {
  const root = tempRoot();
  expectCode(() => new AgentSafeFS({ root, policy: { caseSensitive: true } }), 'CONFIG_INVALID');
  expectCode(
    () => classifyRisk({ relativePath: 'config/file.txt', caseSensitive: true }),
    'RISK_INPUT_INVALID',
  );
  cleanup(root);
});

test('immutable path matching honors case-insensitive policy', () => {
  const root = tempRoot();
  const safe = new AgentSafeFS({ root, policy: { immutable: ['protected'], caseSensitive: false } });
  expectCode(() => safe.proposeWrite({ path: 'PROTECTED/file.txt', content: 'x' }), 'POLICY_DENIED');
  cleanup(root);
});

test('large writes require approval at the configured threshold', () => {
  const root = tempRoot();
  const safe = new AgentSafeFS({ root, policy: { mediumDiffBytes: 4 } });
  const proposal = safe.proposeWrite({ path: 'notes.txt', content: '1234' });
  assert.equal(proposal.risk.level, 'MEDIUM');
  expectCode(() => safe.commit(proposal.operationId), 'APPROVAL_REQUIRED');
  safe.commit(proposal.operationId, { confirmedPath: 'notes.txt' });
  cleanup(root);
});

test('detects change between propose and commit', () => {
  const root = tempRoot();
  const file = path.join(root, 'notes.txt');
  fs.writeFileSync(file, 'before');
  const safe = new AgentSafeFS({ root });
  const proposal = safe.proposeWrite({ path: 'notes.txt', content: 'after' });
  fs.writeFileSync(file, 'someone else changed it');
  expectCode(() => safe.commit(proposal.operationId), 'CONFLICT_CHANGED_SINCE_PROPOSE');
  assert.equal(fs.readFileSync(file, 'utf8'), 'someone else changed it');
  cleanup(root);
});

test('detects a junction introduced after propose and before commit', () => {
  const { base, root, outside } = tempPair();
  fs.mkdirSync(path.join(root, 'dir'));
  const safe = new AgentSafeFS({ root });
  const proposal = safe.proposeWrite({ path: path.join('dir', 'file.txt'), content: 'x' });
  fs.rmSync(path.join(root, 'dir'), { recursive: true });
  createDirectoryLink(outside, path.join(root, 'dir'));
  expectCode(() => safe.commit(proposal.operationId), 'PATH_SYMLINK_ESCAPE');
  assert.equal(fs.existsSync(path.join(outside, 'file.txt')), false);
  cleanup(base);
});

test('detects a hard link introduced after propose and before commit', () => {
  const { base, root, outside } = tempPair();
  const safe = new AgentSafeFS({ root });
  const proposal = safe.proposeWrite({ path: 'file.txt', content: 'agent' });
  const outsideFile = path.join(outside, 'outside.txt');
  fs.writeFileSync(outsideFile, 'outside');
  fs.linkSync(outsideFile, path.join(root, 'file.txt'));
  expectCode(() => safe.commit(proposal.operationId), 'PATH_HARDLINK_DENIED');
  assert.equal(fs.readFileSync(outsideFile, 'utf8'), 'outside');
  cleanup(base);
});

test('snapshot directory junction introduced after construction is rejected before overwrite', () => {
  const { base, root, outside } = tempPair();
  const file = path.join(root, 'notes.txt');
  fs.writeFileSync(file, 'ORIGINAL');
  const safe = new AgentSafeFS({ root });
  const proposal = safe.proposeWrite({ path: 'notes.txt', content: 'CHANGED' });
  fs.mkdirSync(path.join(root, '.agentsafefs'), { recursive: true });
  createDirectoryLink(outside, path.join(root, '.agentsafefs', 'snapshots'));
  expectCode(() => safe.commit(proposal.operationId), 'PATH_SYMLINK_ESCAPE');
  assert.equal(fs.readFileSync(file, 'utf8'), 'ORIGINAL');
  assert.equal(fs.readdirSync(outside).length, 0);
  cleanup(base);
});

test('snapshot parent junction cannot create state directories outside root', () => {
  const { base, root, outside } = tempPair();
  const file = path.join(root, 'notes.txt');
  fs.writeFileSync(file, 'ORIGINAL');
  const safe = new AgentSafeFS({ root });
  const proposal = safe.proposeWrite({ path: 'notes.txt', content: 'CHANGED' });
  createDirectoryLink(outside, path.join(root, '.agentsafefs'));
  expectCode(() => safe.commit(proposal.operationId), 'PATH_SYMLINK_ESCAPE');
  assert.equal(fs.readFileSync(file, 'utf8'), 'ORIGINAL');
  assert.equal(fs.existsSync(path.join(outside, 'snapshots')), false);
  cleanup(base);
});

test('audit parent junction introduced after construction cannot retain a target mutation', () => {
  const { base, root, outside } = tempPair();
  const safe = new AgentSafeFS({ root, auditPath: '.audit-state/audit.jsonl' });
  const proposal = safe.proposeWrite({ path: 'notes.txt', content: 'CHANGED' });
  createDirectoryLink(outside, path.join(root, '.audit-state'));
  expectCode(() => safe.commit(proposal.operationId), 'PATH_SYMLINK_ESCAPE');
  assert.equal(fs.existsSync(path.join(root, 'notes.txt')), false);
  assert.equal(fs.existsSync(path.join(outside, 'audit.jsonl')), false);
  cleanup(base);
});

test('prevents double commit', () => {
  const root = tempRoot();
  const safe = new AgentSafeFS({ root });
  const proposal = safe.proposeWrite({ path: 'notes.txt', content: 'hello' });
  safe.commit(proposal.operationId);
  expectCode(() => safe.commit(proposal.operationId), 'OPERATION_NOT_PENDING');
  cleanup(root);
});

test('expires pending operations at the exact expiration boundary', () => {
  const root = tempRoot();
  let now = 1000;
  const safe = new AgentSafeFS({ root, operationTtlMs: 50, clock: () => now });
  const proposal = safe.proposeWrite({ path: 'notes.txt', content: 'hello' });
  now = 1050;
  expectCode(() => safe.commit(proposal.operationId), 'OPERATION_EXPIRED');
  cleanup(root);
});

test('invalid runtime clocks fail closed', () => {
  const root = tempRoot();
  const safeAtPropose = new AgentSafeFS({ root, clock: () => Number.NaN });
  expectCode(() => safeAtPropose.proposeWrite({ path: 'a.txt', content: 'x' }), 'CLOCK_INVALID');

  let now = 1000;
  const safeAtCommit = new AgentSafeFS({ root, clock: () => now });
  const proposal = safeAtCommit.proposeWrite({ path: 'b.txt', content: 'x' });
  now = Number.NaN;
  expectCode(() => safeAtCommit.commit(proposal.operationId), 'CLOCK_INVALID');
  assert.equal(fs.existsSync(path.join(root, 'b.txt')), false);
  cleanup(root);
});

test('rollback restores previous binary bytes', () => {
  const root = tempRoot();
  const file = path.join(root, 'notes.txt');
  fs.writeFileSync(file, Buffer.from([0, 1, 2, 3]));
  const safe = new AgentSafeFS({ root });
  const proposal = safe.proposeWrite({ path: 'notes.txt', content: 'changed' });
  safe.commit(proposal.operationId);
  safe.rollback(proposal.operationId, { confirmedPath: 'notes.txt' });
  assert.deepEqual(fs.readFileSync(file), Buffer.from([0, 1, 2, 3]));
  expectCode(() => safe.rollback(proposal.operationId, { confirmedPath: 'notes.txt' }), 'ROLLBACK_UNKNOWN_OPERATION');
  cleanup(root);
});

test('rollback of a newly created file removes it', () => {
  const root = tempRoot();
  const safe = new AgentSafeFS({ root });
  const proposal = safe.proposeWrite({ path: 'new.txt', content: 'new' });
  safe.commit(proposal.operationId);
  safe.rollback(proposal.operationId, { confirmedPath: 'new.txt' });
  assert.equal(fs.existsSync(path.join(root, 'new.txt')), false);
  cleanup(root);
});

test('rollback requires exact target confirmation', () => {
  const root = tempRoot();
  fs.writeFileSync(path.join(root, 'notes.txt'), 'before');
  const safe = new AgentSafeFS({ root });
  const proposal = safe.proposeWrite({ path: 'notes.txt', content: 'after' });
  safe.commit(proposal.operationId);
  expectCode(() => safe.rollback(proposal.operationId, { confirmedPath: 'other.txt' }), 'APPROVAL_REQUIRED');
  assert.equal(fs.readFileSync(path.join(root, 'notes.txt'), 'utf8'), 'after');
  cleanup(root);
});

test('rollback refuses if file changed after commit', () => {
  const root = tempRoot();
  const file = path.join(root, 'notes.txt');
  fs.writeFileSync(file, 'before');
  const safe = new AgentSafeFS({ root });
  const proposal = safe.proposeWrite({ path: 'notes.txt', content: 'after' });
  safe.commit(proposal.operationId);
  fs.writeFileSync(file, 'third party change');
  expectCode(() => safe.rollback(proposal.operationId, { confirmedPath: 'notes.txt' }), 'ROLLBACK_CONFLICT');
  assert.equal(fs.readFileSync(file, 'utf8'), 'third party change');
  cleanup(root);
});

test('tampered snapshot is rejected before target bytes are changed', () => {
  const root = tempRoot();
  const file = path.join(root, 'notes.txt');
  fs.writeFileSync(file, 'ORIGINAL');
  const safe = new AgentSafeFS({ root });
  const proposal = safe.proposeWrite({ path: 'notes.txt', content: 'CHANGED' });
  safe.commit(proposal.operationId);
  const snapshot = path.join(root, '.agentsafefs', 'snapshots', `${proposal.operationId}.bin`);
  fs.writeFileSync(snapshot, 'TAMPERED');
  expectCode(() => safe.rollback(proposal.operationId, { confirmedPath: 'notes.txt' }), 'SNAPSHOT_INTEGRITY_FAILED');
  assert.equal(fs.readFileSync(file, 'utf8'), 'CHANGED');
  cleanup(root);
});

test('AgentSafeFS always rejects existing hard-linked targets', () => {
  const { base, root, outside } = tempPair();
  const outsideFile = path.join(outside, 'shared.txt');
  const insideFile = path.join(root, 'shared.txt');
  fs.writeFileSync(outsideFile, 'outside');
  fs.linkSync(outsideFile, insideFile);
  const safe = new AgentSafeFS({ root });
  expectCode(() => safe.proposeWrite({ path: 'shared.txt', content: 'changed' }), 'PATH_HARDLINK_DENIED');
  cleanup(base);
});

test('audit files that are already hard-linked are rejected', () => {
  const { base, root, outside } = tempPair();
  const outsideAudit = path.join(outside, 'audit.jsonl');
  const insideAudit = path.join(root, 'audit.jsonl');
  fs.writeFileSync(outsideAudit, '');
  fs.linkSync(outsideAudit, insideAudit);
  expectCode(() => new AgentSafeFS({ root, auditPath: 'audit.jsonl' }), 'PATH_HARDLINK_DENIED');
  cleanup(base);
});

test('snapshot storage and audit log cannot be targeted by normal writes', () => {
  const root = tempRoot();
  const safe = new AgentSafeFS({ root, auditPath: '.agentsafefs/audit.jsonl' });
  expectCode(() => safe.proposeWrite({ path: '.agentsafefs/snapshots/attack.bin', content: 'x' }), 'PATH_RESERVED_INTERNAL');
  expectCode(() => safe.proposeWrite({ path: '.agentsafefs/audit.jsonl', content: 'x' }), 'PATH_RESERVED_INTERNAL');
  expectCode(() => safe.proposeWrite({ path: '.agentsafefs/audit.jsonl/child.txt', content: 'x' }), 'PATH_RESERVED_INTERNAL');
  expectCode(() => safe.proposeWrite({ path: '.agentsafefs', content: 'x' }), 'PATH_RESERVED_INTERNAL');
  cleanup(root);
});

test('reserved internal paths cannot be bypassed with Unicode normalization aliases', () => {
  const root = tempRoot();
  const safe = new AgentSafeFS({ root, snapshotDir: 'caf\u00e9/snapshots' });
  expectCode(
    () => safe.proposeWrite({ path: 'cafe\u0301/snapshots/attack.bin', content: 'x' }),
    'PATH_RESERVED_INTERNAL',
  );
  cleanup(root);
});

test('audit log reservation is case-insensitive when configured that way', () => {
  const root = tempRoot();
  const safe = new AgentSafeFS({
    root,
    auditPath: '.agentsafefs/Audit.jsonl',
    policy: { caseSensitive: false },
  });
  expectCode(() => safe.proposeWrite({ path: '.AGENTSAFEFS/audit.jsonl', content: 'x' }), 'PATH_RESERVED_INTERNAL');
  cleanup(root);
});

test('commit audit is durable JSONL and does not expose absolute workspace paths', () => {
  const root = tempRoot();
  const auditPath = path.join(root, '.agentsafefs', 'audit.jsonl');
  const safe = new AgentSafeFS({ root, auditPath: '.agentsafefs/audit.jsonl' });
  const proposal = safe.proposeWrite({ path: 'notes.txt', content: 'after' });
  safe.commit(proposal.operationId);
  const entries = fs.readFileSync(auditPath, 'utf8').trim().split(/\r?\n/).map(JSON.parse);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].event, 'commit');
  assert.equal(entries[0].path, 'notes.txt');
  assert.equal(JSON.stringify(entries[0]).includes(root), false);
  assert.equal('snapshotPath' in entries[0], false);
  cleanup(root);
});

test('partial snapshot creation failure is cleaned so the proposal can be retried', () => {
  const root = tempRoot();
  const target = path.join(root, 'notes.txt');
  fs.writeFileSync(target, 'ORIGINAL');
  const safe = new AgentSafeFS({ root });
  const proposal = safe.proposeWrite({ path: 'notes.txt', content: 'CHANGED' });
  const snapshot = path.join(root, '.agentsafefs', 'snapshots', `${proposal.operationId}.bin`);

  const originalOpenSync = fs.openSync;
  const originalFsyncSync = fs.fsyncSync;
  let snapshotFd = null;
  fs.openSync = function patchedOpenSync(filePath, flags, ...rest) {
    const fd = originalOpenSync.call(fs, filePath, flags, ...rest);
    if (path.resolve(String(filePath)) === snapshot && flags === 'wx') snapshotFd = fd;
    return fd;
  };
  fs.fsyncSync = function patchedFsyncSync(fd) {
    if (fd === snapshotFd) {
      const error = new Error('simulated snapshot fsync failure');
      error.code = 'EIO';
      throw error;
    }
    return originalFsyncSync.call(fs, fd);
  };
  try {
    assert.throws(() => safe.commit(proposal.operationId));
  } finally {
    fs.openSync = originalOpenSync;
    fs.fsyncSync = originalFsyncSync;
  }

  assert.equal(fs.existsSync(snapshot), false);
  assert.equal(fs.readFileSync(target, 'utf8'), 'ORIGINAL');
  safe.commit(proposal.operationId);
  assert.equal(fs.readFileSync(target, 'utf8'), 'CHANGED');
  cleanup(root);
});

test('a failed commit cleans its snapshot so the same pending proposal can be retried', () => {
  const root = tempRoot();
  const file = path.join(root, 'notes.txt');
  const audit = path.join(root, 'audit.jsonl');
  fs.writeFileSync(file, 'ORIGINAL');
  const safe = new AgentSafeFS({ root, auditPath: 'audit.jsonl' });
  fs.mkdirSync(audit);
  const proposal = safe.proposeWrite({ path: 'notes.txt', content: 'CHANGED' });
  assert.throws(() => safe.commit(proposal.operationId));
  assert.equal(fs.existsSync(path.join(root, '.agentsafefs', 'snapshots', `${proposal.operationId}.bin`)), false);
  fs.rmSync(audit, { recursive: true });
  safe.commit(proposal.operationId);
  assert.equal(fs.readFileSync(file, 'utf8'), 'CHANGED');
  cleanup(root);
});

test('commit audit failure restores an existing target before reporting failure', () => {
  const root = tempRoot();
  const file = path.join(root, 'notes.txt');
  fs.writeFileSync(file, 'ORIGINAL');
  const safe = new AgentSafeFS({ root, auditPath: 'audit.jsonl' });
  fs.mkdirSync(path.join(root, 'audit.jsonl'));
  const proposal = safe.proposeWrite({ path: 'notes.txt', content: 'CHANGED' });
  assert.throws(() => safe.commit(proposal.operationId));
  assert.equal(fs.readFileSync(file, 'utf8'), 'ORIGINAL');
  cleanup(root);
});

test('commit audit failure removes a newly created target before reporting failure', () => {
  const root = tempRoot();
  const safe = new AgentSafeFS({ root, auditPath: 'audit.jsonl' });
  fs.mkdirSync(path.join(root, 'audit.jsonl'));
  const proposal = safe.proposeWrite({ path: 'new.txt', content: 'CHANGED' });
  assert.throws(() => safe.commit(proposal.operationId));
  assert.equal(fs.existsSync(path.join(root, 'new.txt')), false);
  cleanup(root);
});

test('commit recovery never overwrites a third-party change made after mutation', () => {
  const root = tempRoot();
  const target = path.join(root, 'notes.txt');
  const audit = path.join(root, 'audit.jsonl');
  fs.writeFileSync(target, 'ORIGINAL');
  const safe = new AgentSafeFS({ root, auditPath: 'audit.jsonl' });
  const proposal = safe.proposeWrite({ path: 'notes.txt', content: 'COMMITTED' });

  const originalOpenSync = fs.openSync;
  fs.openSync = function patchedOpenSync(filePath, flags, ...rest) {
    if (path.resolve(String(filePath)) === audit && flags === 'a') {
      fs.writeFileSync(target, 'THIRD_PARTY');
      const error = new Error('simulated audit failure');
      error.code = 'EIO';
      throw error;
    }
    return originalOpenSync.call(fs, filePath, flags, ...rest);
  };
  try {
    expectCode(() => safe.commit(proposal.operationId), 'COMMIT_RECOVERY_FAILED');
  } finally {
    fs.openSync = originalOpenSync;
  }

  assert.equal(fs.readFileSync(target, 'utf8'), 'THIRD_PARTY');
  cleanup(root);
});

test('commit recovery never deletes a third-party replacement of a newly created target', () => {
  const root = tempRoot();
  const target = path.join(root, 'new.txt');
  const audit = path.join(root, 'audit.jsonl');
  const safe = new AgentSafeFS({ root, auditPath: 'audit.jsonl' });
  const proposal = safe.proposeWrite({ path: 'new.txt', content: 'COMMITTED' });

  const originalOpenSync = fs.openSync;
  fs.openSync = function patchedOpenSync(filePath, flags, ...rest) {
    if (path.resolve(String(filePath)) === audit && flags === 'a') {
      fs.writeFileSync(target, 'THIRD_PARTY');
      const error = new Error('simulated audit failure');
      error.code = 'EIO';
      throw error;
    }
    return originalOpenSync.call(fs, filePath, flags, ...rest);
  };
  try {
    expectCode(() => safe.commit(proposal.operationId), 'COMMIT_RECOVERY_FAILED');
  } finally {
    fs.openSync = originalOpenSync;
  }

  assert.equal(fs.readFileSync(target, 'utf8'), 'THIRD_PARTY');
  cleanup(root);
});

test('rollback audit failure restores the committed state before reporting failure', () => {
  const root = tempRoot();
  const audit = path.join(root, 'audit.jsonl');
  const file = path.join(root, 'notes.txt');
  fs.writeFileSync(file, 'ORIGINAL');
  const safe = new AgentSafeFS({ root, auditPath: 'audit.jsonl' });
  const proposal = safe.proposeWrite({ path: 'notes.txt', content: 'COMMITTED' });
  safe.commit(proposal.operationId);
  fs.rmSync(audit);
  fs.mkdirSync(audit);
  assert.throws(() => safe.rollback(proposal.operationId, { confirmedPath: 'notes.txt' }));
  assert.equal(fs.readFileSync(file, 'utf8'), 'COMMITTED');
  cleanup(root);
});

test('rollback recovery never overwrites a third-party change made after rollback mutation', () => {
  const root = tempRoot();
  const audit = path.join(root, 'audit.jsonl');
  const target = path.join(root, 'notes.txt');
  fs.writeFileSync(target, 'ORIGINAL');
  const safe = new AgentSafeFS({ root, auditPath: 'audit.jsonl' });
  const proposal = safe.proposeWrite({ path: 'notes.txt', content: 'COMMITTED' });
  safe.commit(proposal.operationId);

  const originalOpenSync = fs.openSync;
  fs.openSync = function patchedOpenSync(filePath, flags, ...rest) {
    if (path.resolve(String(filePath)) === audit && flags === 'a') {
      fs.writeFileSync(target, 'THIRD_PARTY');
      const error = new Error('simulated audit failure');
      error.code = 'EIO';
      throw error;
    }
    return originalOpenSync.call(fs, filePath, flags, ...rest);
  };
  try {
    expectCode(
      () => safe.rollback(proposal.operationId, { confirmedPath: 'notes.txt' }),
      'ROLLBACK_RECOVERY_FAILED',
    );
  } finally {
    fs.openSync = originalOpenSync;
  }

  assert.equal(fs.readFileSync(target, 'utf8'), 'THIRD_PARTY');
  cleanup(root);
});

test('rollback recovery never overwrites a third-party replacement of a removed new target', () => {
  const root = tempRoot();
  const audit = path.join(root, 'audit.jsonl');
  const target = path.join(root, 'new.txt');
  const safe = new AgentSafeFS({ root, auditPath: 'audit.jsonl' });
  const proposal = safe.proposeWrite({ path: 'new.txt', content: 'COMMITTED' });
  safe.commit(proposal.operationId);

  const originalOpenSync = fs.openSync;
  fs.openSync = function patchedOpenSync(filePath, flags, ...rest) {
    if (path.resolve(String(filePath)) === audit && flags === 'a') {
      fs.writeFileSync(target, 'THIRD_PARTY');
      const error = new Error('simulated audit failure');
      error.code = 'EIO';
      throw error;
    }
    return originalOpenSync.call(fs, filePath, flags, ...rest);
  };
  try {
    expectCode(
      () => safe.rollback(proposal.operationId, { confirmedPath: 'new.txt' }),
      'ROLLBACK_RECOVERY_FAILED',
    );
  } finally {
    fs.openSync = originalOpenSync;
  }

  assert.equal(fs.readFileSync(target, 'utf8'), 'THIRD_PARTY');
  cleanup(root);
});

test('snapshot hard-link replacement is rejected before rollback mutation', () => {
  const { base, root, outside } = tempPair();
  const target = path.join(root, 'notes.txt');
  const outsideFile = path.join(outside, 'payload.bin');
  fs.writeFileSync(target, 'ORIGINAL');
  fs.writeFileSync(outsideFile, 'ORIGINAL');
  const safe = new AgentSafeFS({ root });
  const proposal = safe.proposeWrite({ path: 'notes.txt', content: 'CHANGED' });
  safe.commit(proposal.operationId);
  const snapshot = path.join(root, '.agentsafefs', 'snapshots', `${proposal.operationId}.bin`);
  fs.rmSync(snapshot);
  fs.linkSync(outsideFile, snapshot);
  expectCode(() => safe.rollback(proposal.operationId, { confirmedPath: 'notes.txt' }), 'PATH_HARDLINK_DENIED');
  assert.equal(fs.readFileSync(target, 'utf8'), 'CHANGED');
  cleanup(base);
});

test('existing POSIX file mode is preserved across overwrite and rollback', { skip: process.platform === 'win32' }, () => {
  const root = tempRoot();
  const file = path.join(root, 'script.txt');
  fs.writeFileSync(file, 'before', { mode: 0o640 });
  fs.chmodSync(file, 0o640);
  const safe = new AgentSafeFS({ root });
  const proposal = safe.proposeWrite({ path: 'script.txt', content: 'after' });
  safe.commit(proposal.operationId);
  assert.equal(fs.statSync(file).mode & 0o777, 0o640);
  safe.rollback(proposal.operationId, { confirmedPath: 'script.txt' });
  assert.equal(fs.statSync(file).mode & 0o777, 0o640);
  cleanup(root);
});

test('new POSIX files use the secure configured mode', { skip: process.platform === 'win32' }, () => {
  const root = tempRoot();
  const safe = new AgentSafeFS({ root, newFileMode: 0o640 });
  const proposal = safe.proposeWrite({ path: 'new.txt', content: 'x' });
  safe.commit(proposal.operationId);
  assert.equal(fs.statSync(path.join(root, 'new.txt')).mode & 0o777, 0o640);
  cleanup(root);
});

test('successful commit and rollback both appear in audit log', () => {
  const root = tempRoot();
  fs.writeFileSync(path.join(root, 'notes.txt'), 'before');
  const safe = new AgentSafeFS({ root, auditPath: '.agentsafefs/audit.jsonl' });
  const proposal = safe.proposeWrite({ path: 'notes.txt', content: 'after' });
  safe.commit(proposal.operationId);
  safe.rollback(proposal.operationId, { confirmedPath: 'notes.txt' });
  const entries = fs.readFileSync(path.join(root, '.agentsafefs', 'audit.jsonl'), 'utf8')
    .trim().split(/\r?\n/).map(JSON.parse);
  assert.deepEqual(entries.map((entry) => entry.event), ['commit', 'rollback']);
  assert.equal(fs.existsSync(path.join(root, '.agentsafefs', 'snapshots', `${proposal.operationId}.bin`)), false);
  cleanup(root);
});
