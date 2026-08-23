import fs from 'node:fs';
import path from 'node:path';
import { fail } from './errors.mjs';

const DEFAULT_SECRET_PATTERNS = Object.freeze([
  /^\.env(?:\.|$)/i,
  /(?:^|[._-])(secret|secrets|credential|credentials|token|tokens)(?:[._-]|$)/i,
  /\.(?:pem|key|p12|pfx)$/i,
]);

const WINDOWS_DEVICE_BASENAMES = /^(?:con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³]|conin\$|conout\$)$/i;

function defaultCaseSensitive() {
  return process.platform !== 'win32' && process.platform !== 'darwin';
}

function normalizeForComparison(value, caseSensitive) {
  const resolved = path.resolve(value).normalize('NFC');
  return caseSensitive ? resolved : resolved.toLocaleLowerCase('en-US');
}

export function canonicalize(input) {
  if (typeof input !== 'string' || input.length === 0 || input.includes('\0')) {
    fail('PATH_INPUT_INVALID', 'Path must be a non-empty string without NUL bytes');
  }
  return path.resolve(input);
}

export function realPathOrNull(input) {
  try {
    return fs.realpathSync.native(input);
  } catch {
    return null;
  }
}

export function isInside(root, candidate, { caseSensitive = defaultCaseSensitive() } = {}) {
  if (process.platform === 'win32') caseSensitive = false;
  const normalizedRoot = normalizeForComparison(root, caseSensitive);
  const normalizedCandidate = normalizeForComparison(candidate, caseSensitive);
  if (normalizedCandidate === normalizedRoot) return true;
  const rootWithSep = normalizedRoot.endsWith(path.sep) ? normalizedRoot : normalizedRoot + path.sep;
  return normalizedCandidate.startsWith(rootWithSep);
}

function isWithinRootBoundary(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (
    relative !== '..' &&
    !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative)
  );
}

function testPattern(pattern, value) {
  pattern.lastIndex = 0;
  return pattern.test(value);
}

function hasSecretLikeSegment(relativePath, patterns) {
  return relativePath
    .split(/[\\/]+/)
    .filter(Boolean)
    .some((segment) => patterns.some((pattern) => testPattern(pattern, segment)));
}

function validateWindowsSegments(relativePath) {
  if (process.platform !== 'win32') return;
  const segments = relativePath.split(/[\\/]+/).filter(Boolean);
  for (const segment of segments) {
    if (segment.includes(':')) {
      fail('PATH_WINDOWS_ADS', 'NTFS alternate data streams are not allowed', { segment });
    }
    if (segment.endsWith('.') || segment.endsWith(' ')) {
      fail('PATH_WINDOWS_ALIAS', 'Windows path segments may not end with a dot or space', { segment });
    }
    const deviceBase = segment.split('.')[0].replace(/[ .]+$/g, '');
    if (WINDOWS_DEVICE_BASENAMES.test(deviceBase)) {
      fail('PATH_WINDOWS_DEVICE', 'Windows reserved device names are not allowed', { segment });
    }
  }
}

function lstatOrNull(input) {
  try {
    return fs.lstatSync(input);
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

function canonicalizeExistingPrefix(root, candidate) {
  const relative = path.relative(root, candidate);
  if (!relative) return root;

  const parts = relative.split(path.sep).filter(Boolean);
  let current = root;
  let deepestExisting = root;
  let existingParts = 0;
  for (let index = 0; index < parts.length; index += 1) {
    current = path.join(current, parts[index]);
    if (!lstatOrNull(current)) break;
    deepestExisting = current;
    existingParts = index + 1;
  }

  const canonicalExisting = fs.realpathSync.native(deepestExisting);
  return path.resolve(canonicalExisting, ...parts.slice(existingParts));
}

function assertNoLinksOrUnsafeTarget({ root, candidate, allowTargetDirectory }) {
  const relative = path.relative(root, candidate);
  if (!relative) {
    if (!allowTargetDirectory) fail('PATH_TARGET_IS_DIRECTORY', 'Target path is a directory');
    return;
  }

  const parts = relative.split(path.sep).filter(Boolean);
  let current = root;
  for (let index = 0; index < parts.length; index += 1) {
    current = path.join(current, parts[index]);
    const stat = lstatOrNull(current);
    if (!stat) break;

    if (stat.isSymbolicLink()) {
      fail('PATH_SYMLINK_ESCAPE', 'Symbolic links and junctions are not allowed in guarded paths', {
        segment: path.relative(root, current),
      });
    }

    const isTarget = index === parts.length - 1;
    if (!isTarget && !stat.isDirectory()) {
      fail('PATH_PARENT_NOT_DIRECTORY', 'A parent path component is not a directory', {
        segment: path.relative(root, current),
      });
    }

    if (isTarget && stat.isDirectory() && !allowTargetDirectory) {
      fail('PATH_TARGET_IS_DIRECTORY', 'Target path is a directory');
    }

    if (isTarget && !stat.isDirectory() && !stat.isFile()) {
      fail('PATH_SPECIAL_FILE_DENIED', 'Special filesystem objects are not valid write targets');
    }

    if (isTarget && stat.isFile() && Number(stat.nlink) > 1) {
      fail('PATH_HARDLINK_DENIED', 'Existing hard-linked files are denied by default');
    }
  }
}

export function resolveSafePath({
  root,
  inputPath,
  denySecretLikeNames = true,
  secretPatterns = DEFAULT_SECRET_PATTERNS,
  allowTargetDirectory = false,
}) {
  if (typeof root !== 'string' || root.length === 0 || typeof inputPath !== 'string' || inputPath.length === 0) {
    fail('PATH_INPUT_INVALID', 'root and inputPath must be non-empty strings');
  }
  if (typeof denySecretLikeNames !== 'boolean' || typeof allowTargetDirectory !== 'boolean') {
    fail('PATH_INPUT_INVALID', 'Path safety flags must be boolean');
  }
  if (!Array.isArray(secretPatterns) || secretPatterns.some((pattern) => !(pattern instanceof RegExp))) {
    fail('PATH_INPUT_INVALID', 'secretPatterns must be an array of RegExp values');
  }
  if (process.platform === 'win32' && /^(?:\\\\[?.]\\|\/\/[?.]\/)/.test(inputPath)) {
    fail('PATH_WINDOWS_NAMESPACE', 'Windows device and extended-length namespace paths are not allowed');
  }

  const requestedRoot = canonicalize(root);
  const rootStat = lstatOrNull(requestedRoot);
  if (!rootStat) fail('ROOT_NOT_FOUND', 'Configured root does not exist');
  if (rootStat.isSymbolicLink()) fail('ROOT_SYMLINK_DENIED', 'Configured root may not itself be a symlink or junction');
  if (!rootStat.isDirectory()) fail('ROOT_NOT_DIRECTORY', 'Configured root must be a directory');

  const realRoot = fs.realpathSync.native(requestedRoot);
  let candidate = path.isAbsolute(inputPath)
    ? canonicalize(inputPath)
    : canonicalize(path.join(realRoot, inputPath));

  // Root containment follows the host path semantics, not policy matching.
  // On POSIX this stays case-sensitive even when policy matching is configured
  // case-insensitively; otherwise a case-variant absolute path could escape a
  // case-sensitive filesystem root.
  if (!isWithinRootBoundary(realRoot, candidate)) {
    fail('PATH_OUTSIDE_ROOT', 'Path escapes the configured root', { inputPath });
  }

  const lexicalRelativePath = path.relative(realRoot, candidate);
  validateWindowsSegments(lexicalRelativePath);
  assertNoLinksOrUnsafeTarget({ root: realRoot, candidate, allowTargetDirectory });

  // Resolve the deepest existing prefix after link checks. On Windows this
  // expands NTFS 8.3 short-name aliases (for example PROTEC~1) back to their
  // canonical long names before policy, secret-name, approval, and reserved-
  // path logic sees the result. Non-existing descendants are appended unchanged.
  candidate = canonicalizeExistingPrefix(realRoot, candidate);
  if (!isWithinRootBoundary(realRoot, candidate)) {
    fail('PATH_OUTSIDE_ROOT', 'Canonical path escapes the configured root', { inputPath });
  }

  const relativePath = path.relative(realRoot, candidate);
  validateWindowsSegments(relativePath);
  if (denySecretLikeNames && hasSecretLikeSegment(relativePath, secretPatterns)) {
    fail('PATH_SECRET_LIKE', 'Path looks like it may contain credentials or secrets', { inputPath });
  }

  assertNoLinksOrUnsafeTarget({ root: realRoot, candidate, allowTargetDirectory });
  return candidate;
}

export function toPortableRelative(root, candidate) {
  return path.relative(root, candidate).split(path.sep).join('/');
}

export { DEFAULT_SECRET_PATTERNS };
