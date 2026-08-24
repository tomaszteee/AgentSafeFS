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
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const packageVersion = pkg.version;
if (!/^\d+\.\d+\.\d+(?:[-+].*)?$/.test(packageVersion)) {
  throw new Error(`Unsupported package version for standalone metadata: ${packageVersion}`);
}
const baseVersion = packageVersion.split(/[+-]/, 1)[0];
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
const stagingPath = path.join(work, `${outputName}.staging`);
fs.copyFileSync(process.execPath, stagingPath);

function stripWindowsAuthenticode(filePath) {
  const bytes = fs.readFileSync(filePath);
  if (bytes.length < 0x100 || bytes.toString('ascii', 0, 2) !== 'MZ') {
    throw new Error('Windows runtime is not a valid PE file');
  }
  const peOffset = bytes.readUInt32LE(0x3c);
  if (bytes.toString('ascii', peOffset, peOffset + 4) !== 'PE\0\0') {
    throw new Error('Windows runtime has no valid PE signature');
  }
  const optionalHeader = peOffset + 24;
  const magic = bytes.readUInt16LE(optionalHeader);
  const dataDirectoryOffset = optionalHeader + (magic === 0x20b ? 112 : magic === 0x10b ? 96 : -1);
  if (dataDirectoryOffset < optionalHeader) throw new Error(`Unsupported PE optional-header magic: 0x${magic.toString(16)}`);
  const securityDirectory = dataDirectoryOffset + (4 * 8);
  const certificateOffset = bytes.readUInt32LE(securityDirectory);
  const certificateSize = bytes.readUInt32LE(securityDirectory + 4);
  if (!certificateOffset && !certificateSize) return;
  if (!certificateOffset || !certificateSize || certificateOffset + certificateSize !== bytes.length) {
    throw new Error('Refusing to strip an unexpected/non-terminal PE certificate table');
  }
  bytes.writeUInt32LE(0, securityDirectory);
  bytes.writeUInt32LE(0, securityDirectory + 4);
  fs.writeFileSync(filePath, bytes.subarray(0, certificateOffset));
}

if (process.platform === 'win32') stripWindowsAuthenticode(stagingPath);

if (process.platform === 'darwin') {
  try {
    execFileSync('codesign', ['--remove-signature', stagingPath], { stdio: 'inherit' });
  } catch {
    // A runner-provided Node binary may already be unsigned; injection can proceed.
  }
}

const postjectCli = path.join(root, 'node_modules', 'postject', 'dist', 'cli.js');
const postjectArgs = [postjectCli, stagingPath, 'NODE_SEA_BLOB', blob, '--sentinel-fuse', SENTINEL];
if (process.platform === 'darwin') postjectArgs.push('--macho-segment-name', 'NODE_SEA');
execFileSync(process.execPath, postjectArgs, { cwd: root, stdio: 'inherit' });

if (process.platform === 'win32') {
  const ResEdit = await import('resedit');
  const executable = ResEdit.NtExecutable.from(fs.readFileSync(stagingPath));
  const resources = ResEdit.NtExecutableResource.from(executable);
  const versionInfo = ResEdit.Resource.VersionInfo.fromEntries(resources.entries)[0];
  if (!versionInfo) throw new Error('Windows runtime contains no version-info resource');
  versionInfo.setFileVersion(baseVersion, 1033);
  versionInfo.setProductVersion(baseVersion, 1033);
  versionInfo.setStringValues(
    { lang: 1033, codepage: 1200 },
    {
      CompanyName: 'AgentSafeFS contributors',
      ProductName: 'AgentSafeFS',
      FileDescription: 'AgentSafeFS guarded filesystem CLI',
      InternalName: 'agentsafefs',
      OriginalFilename: outputName,
      LegalCopyright: 'Copyright AgentSafeFS contributors',
      Comments: 'https://github.com/tomaszteee/AgentSafeFS',
    },
  );
  versionInfo.outputToResourceEntries(resources.entries);
  resources.outputResource(executable);
  fs.writeFileSync(stagingPath, Buffer.from(executable.generate()));

  const escaped = stagingPath.replaceAll("'", "''");
  const metadataRaw = execFileSync('powershell.exe', ['-NoProfile', '-Command',
    `$v=(Get-Item -LiteralPath '${escaped}').VersionInfo; [pscustomobject]@{ProductName=$v.ProductName;ProductVersion=$v.ProductVersion;FileDescription=$v.FileDescription;OriginalFilename=$v.OriginalFilename}|ConvertTo-Json -Compress`
  ], { encoding: 'utf8' });
  const metadata = JSON.parse(metadataRaw);
  if (metadata.ProductName !== 'AgentSafeFS') throw new Error(`Windows ProductName mismatch: ${metadata.ProductName}`);
  if (!String(metadata.ProductVersion).startsWith(baseVersion)) {
    throw new Error(`Windows ProductVersion mismatch: ${metadata.ProductVersion}`);
  }
  if (metadata.OriginalFilename !== outputName) throw new Error(`Windows OriginalFilename mismatch: ${metadata.OriginalFilename}`);
}

if (process.platform === 'darwin') {
  execFileSync('codesign', ['--force', '--sign', '-', stagingPath], { stdio: 'inherit' });
}
if (process.platform !== 'win32') fs.chmodSync(stagingPath, 0o755);

if (fs.existsSync(outputPath)) {
  try {
    fs.rmSync(outputPath, { force: true });
  } catch {
    const stalePath = path.join(dist, `${outputName}.stale-${Date.now()}`);
    fs.renameSync(outputPath, stalePath);
  }
}
fs.renameSync(stagingPath, outputPath);

const version = execFileSync(outputPath, ['--version'], { encoding: 'utf8' }).trim();
if (version !== packageVersion) throw new Error(`Standalone binary version mismatch: ${version}`);
execFileSync(outputPath, ['doctor', '--root', os.tmpdir(), '--json'], { stdio: 'pipe' });

fs.rmSync(work, { recursive: true, force: true });
process.stdout.write(`${outputPath}\n`);
