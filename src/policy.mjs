import path from 'node:path';
import { fail } from './errors.mjs';

const DEFAULT_HIGH_RISK_EXTENSIONS = Object.freeze([
  '.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1', '.sh', '.py', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx'
]);

function defaultCaseSensitive() {
  return process.platform !== 'win32' && process.platform !== 'darwin';
}

function normalizeRel(value, caseSensitive) {
  let normalized = String(value).replaceAll('\\', '/').replace(/^\.\//, '').replace(/\/+$/, '');
  normalized = path.posix.normalize(normalized).normalize('NFC');
  if (normalized === '.') normalized = '';
  return caseSensitive ? normalized : normalized.toLocaleLowerCase('en-US');
}

function matchesPrefix(relativePath, prefixes = [], caseSensitive) {
  const rel = normalizeRel(relativePath, caseSensitive);
  return prefixes.some((prefix) => {
    const p = normalizeRel(prefix, caseSensitive);
    return rel === p || rel.startsWith(p + '/');
  });
}

export function isValidPolicyPrefix(value) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) return false;
  const slash = value.replaceAll('\\', '/');
  if (slash.split('/').includes('..')) return false;
  const normalized = path.posix.normalize(slash.replace(/^\.\//, ''));
  return !(
    normalized === '' ||
    normalized === '.' ||
    normalized === '..' ||
    normalized.startsWith('../') ||
    path.posix.isAbsolute(normalized) ||
    /^[a-zA-Z]:\//.test(normalized)
  );
}

export function classifyRisk(options = {}) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    fail('RISK_INPUT_INVALID', 'options must be an object');
  }
  const allowedKeys = new Set([
    'relativePath',
    'operation',
    'diffBytes',
    'immutable',
    'protectedPaths',
    'sensitiveAreas',
    'highRiskExtensions',
    'mediumDiffBytes',
    'caseSensitive',
  ]);
  const unknownKeys = Object.keys(options).filter((key) => !allowedKeys.has(key));
  if (unknownKeys.length > 0) {
    fail('RISK_INPUT_INVALID', 'Unknown risk-classifier option', { unknownKeys });
  }
  const {
    relativePath,
    operation = 'write',
    diffBytes = 0,
    immutable = [],
    protectedPaths = [],
    sensitiveAreas = [],
    highRiskExtensions = DEFAULT_HIGH_RISK_EXTENSIONS,
    mediumDiffBytes = 16_384,
    caseSensitive = defaultCaseSensitive(),
  } = options;
  if (typeof relativePath !== 'string' || relativePath.length === 0) {
    fail('RISK_INPUT_INVALID', 'relativePath must be a non-empty relative path');
  }
  const normalizedInput = relativePath.replaceAll('\\', '/');
  const normalizedPath = path.posix.normalize(normalizedInput);
  if (
    normalizedPath === '' ||
    normalizedPath === '.' ||
    normalizedPath === '..' ||
    normalizedPath.startsWith('../') ||
    path.posix.isAbsolute(normalizedPath) ||
    /^[a-zA-Z]:\//.test(normalizedPath)
  ) {
    fail('RISK_INPUT_INVALID', 'relativePath must stay within a relative path namespace');
  }
  if (!['write', 'delete', 'move'].includes(operation)) {
    fail('RISK_INPUT_INVALID', 'operation must be write, delete, or move');
  }
  if (!Number.isFinite(diffBytes) || diffBytes < 0) {
    fail('RISK_INPUT_INVALID', 'diffBytes must be a non-negative finite number');
  }
  for (const [name, values] of Object.entries({ immutable, protectedPaths, sensitiveAreas })) {
    if (!Array.isArray(values) || values.some((value) => !isValidPolicyPrefix(value))) {
      fail('RISK_INPUT_INVALID', `${name} must contain safe non-empty relative path prefixes`);
    }
  }
  if (!(highRiskExtensions instanceof Set) && !Array.isArray(highRiskExtensions)) {
    fail('RISK_INPUT_INVALID', 'highRiskExtensions must be a Set or array of strings');
  }
  if ([...highRiskExtensions].some((value) => typeof value !== 'string' || value.length === 0)) {
    fail('RISK_INPUT_INVALID', 'highRiskExtensions must contain non-empty strings');
  }
  if (!Number.isFinite(mediumDiffBytes) || mediumDiffBytes < 0) {
    fail('RISK_INPUT_INVALID', 'mediumDiffBytes must be a non-negative finite number');
  }
  if (typeof caseSensitive !== 'boolean') {
    fail('RISK_INPUT_INVALID', 'caseSensitive must be boolean');
  }
  if ((process.platform === 'win32' || process.platform === 'darwin') && caseSensitive === true) {
    fail('RISK_INPUT_INVALID', 'caseSensitive=true is unsafe and unsupported on Windows and macOS');
  }
  const effectiveCaseSensitive = (process.platform === 'win32' || process.platform === 'darwin')
    ? false
    : caseSensitive;
  if (matchesPrefix(relativePath, immutable, effectiveCaseSensitive)) {
    return { level: 'DENY', reason: 'IMMUTABLE_PATH', requiresApproval: false };
  }

  if (operation === 'delete' || operation === 'move') {
    return { level: 'HIGH', reason: `OPERATION_${operation.toUpperCase()}`, requiresApproval: true };
  }

  if (
    matchesPrefix(relativePath, protectedPaths, effectiveCaseSensitive) ||
    matchesPrefix(relativePath, sensitiveAreas, effectiveCaseSensitive)
  ) {
    return { level: 'HIGH', reason: 'PROTECTED_OR_SENSITIVE_PATH', requiresApproval: true };
  }

  const extension = path.extname(relativePath).toLowerCase();
  const extensionSet = new Set([...highRiskExtensions].map((value) => {
    const lower = String(value).toLowerCase();
    return lower.startsWith('.') ? lower : `.${lower}`;
  }));
  if (extensionSet.has(extension)) {
    return { level: 'HIGH', reason: 'HIGH_RISK_EXTENSION', requiresApproval: true };
  }

  if (diffBytes >= mediumDiffBytes) {
    return { level: 'MEDIUM', reason: 'LARGE_CHANGE', requiresApproval: true };
  }

  return { level: 'LOW', reason: 'STANDARD_CHANGE', requiresApproval: false };
}

export { DEFAULT_HIGH_RISK_EXTENSIONS };
