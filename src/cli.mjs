#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { isSea } from 'node:sea';
import { AgentSafeFS, AgentSafeFSError } from './index.mjs';

const CLI_VERSION = '0.2.1';

class CliError extends Error {
  constructor(code, message, details = null) {
    super(message);
    this.name = 'CliError';
    this.code = code;
    this.details = details;
  }
}

const VALUE_OPTIONS = new Set(['root', 'config', 'target', 'from', 'text', 'approve']);
const BOOLEAN_OPTIONS = new Set(['stdin', 'json', 'help', 'version']);
const SHORT_OPTIONS = new Map([
  ['-h', '--help'],
  ['-V', '--version'],
  ['-r', '--root'],
  ['-c', '--config'],
  ['-t', '--target'],
  ['-f', '--from'],
  ['-a', '--approve'],
]);

function usageError(message, details = null) {
  throw new CliError('CLI_USAGE', message, details);
}

function parseArgv(argv) {
  const options = Object.create(null);
  let command = null;

  for (let index = 0; index < argv.length; index += 1) {
    let token = argv[index];
    if (SHORT_OPTIONS.has(token)) token = SHORT_OPTIONS.get(token);

    if (!token.startsWith('-')) {
      if (command !== null) usageError(`Unexpected positional argument: ${token}`);
      command = token;
      continue;
    }

    if (token === '--') usageError('Positional arguments after -- are not supported');
    if (!token.startsWith('--')) usageError(`Unknown option: ${token}`);

    const equalsIndex = token.indexOf('=');
    const key = token.slice(2, equalsIndex === -1 ? undefined : equalsIndex);
    const inlineValue = equalsIndex === -1 ? null : token.slice(equalsIndex + 1);

    if (!VALUE_OPTIONS.has(key) && !BOOLEAN_OPTIONS.has(key)) usageError(`Unknown option: --${key}`);
    if (Object.hasOwn(options, key)) usageError(`Option --${key} may only be provided once`);

    if (BOOLEAN_OPTIONS.has(key)) {
      if (inlineValue !== null) usageError(`Option --${key} does not take a value`);
      options[key] = true;
      continue;
    }

    let value = inlineValue;
    if (value === null) {
      index += 1;
      if (index >= argv.length) usageError(`Option --${key} requires a value`);
      value = argv[index];
    }
    if (value.length === 0) usageError(`Option --${key} requires a non-empty value`);
    options[key] = value;
  }

  return { command, options };
}

function loadConfig(cwd, explicitPath) {
  const configPath = explicitPath ? path.resolve(cwd, explicitPath) : null;

  if (!configPath) return { configPath: null, configDir: cwd, config: {} };
  if (!fs.existsSync(configPath)) {
    throw new CliError('CLI_CONFIG_NOT_FOUND', 'Configuration file does not exist', { configPath });
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  } catch (error) {
    throw new CliError('CLI_CONFIG_INVALID', 'Configuration file is not valid JSON', {
      configPath,
      cause: error instanceof Error ? error.message : String(error),
    });
  }

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new CliError('CLI_CONFIG_INVALID', 'Configuration must be a JSON object', { configPath });
  }

  const allowed = new Set(['root', 'policy', 'operationTtlMs', 'auditPath', 'snapshotDir', 'newFileMode']);
  const unknownKeys = Object.keys(parsed).filter((key) => !allowed.has(key));
  if (unknownKeys.length > 0) {
    throw new CliError('CLI_CONFIG_INVALID', 'Unknown configuration key', { configPath, unknownKeys });
  }

  if (parsed.root !== undefined && (typeof parsed.root !== 'string' || parsed.root.length === 0)) {
    throw new CliError('CLI_CONFIG_INVALID', 'config.root must be a non-empty string', { configPath });
  }

  return { configPath, configDir: path.dirname(configPath), config: parsed };
}

function resolveAgentOptions(cwd, cliOptions) {
  const loaded = loadConfig(cwd, cliOptions.config);
  const { config } = loaded;
  const configuredRoot = cliOptions.root ?? config.root ?? cwd;
  const rootBase = cliOptions.root !== undefined ? cwd : (config.root !== undefined ? loaded.configDir : cwd);
  const resolvedRoot = path.resolve(rootBase, configuredRoot);

  const agentOptions = {
    ...config,
    root: resolvedRoot,
  };
  delete agentOptions.root;
  agentOptions.root = resolvedRoot;

  return { ...loaded, agentOptions };
}

function readContent(cwd, options) {
  const selectors = ['from', 'text', 'stdin'].filter((key) => options[key] !== undefined);
  if (selectors.length !== 1) {
    usageError('Exactly one content source is required: --from <file>, --text <text>, or --stdin');
  }

  if (options.from !== undefined) {
    const sourcePath = path.resolve(cwd, options.from);
    try {
      return { content: fs.readFileSync(sourcePath), source: { type: 'file', path: sourcePath } };
    } catch (error) {
      throw new CliError('CLI_INPUT_READ_FAILED', 'Could not read input file', {
        sourcePath,
        cause: error instanceof Error ? error.message : String(error),
      });
    }
  }

  if (options.text !== undefined) {
    return { content: options.text, source: { type: 'text' } };
  }

  try {
    return { content: fs.readFileSync(0), source: { type: 'stdin' } };
  } catch (error) {
    throw new CliError('CLI_INPUT_READ_FAILED', 'Could not read standard input', {
      cause: error instanceof Error ? error.message : String(error),
    });
  }
}

function assertOptionsAllowed(command, options) {
  const common = new Set(['root', 'config', 'json', 'help', 'version']);
  const allowed = command === 'doctor'
    ? common
    : new Set([
        ...common,
        'target',
        'from',
        'text',
        'stdin',
        ...(command === 'write' ? ['approve'] : []),
      ]);
  const invalid = Object.keys(options).filter((key) => !allowed.has(key));
  if (invalid.length > 0) usageError(`Option not valid for ${command}: --${invalid[0]}`);
}

function requireTarget(options) {
  if (typeof options.target !== 'string' || options.target.length === 0) {
    usageError('Command requires --target <relative-path>');
  }
  return options.target;
}

function jsonSafe(value) {
  return JSON.parse(JSON.stringify(value));
}

function printJson(payload) {
  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
}

function printProposal(proposal) {
  const approval = proposal.risk.requiresApproval ? 'required' : 'not required';
  process.stdout.write([
    `Plan: ${proposal.path}`,
    `Risk: ${proposal.risk.level} (${proposal.risk.reason})`,
    `Approval: ${approval}`,
    `Bytes: ${proposal.bytesBefore} -> ${proposal.bytesAfter}`,
    `SHA-256 before: ${proposal.sha256Before ?? '(new file)'}`,
    `SHA-256 after:  ${proposal.sha256After}`,
    'No files were changed.',
    '',
  ].join('\n'));
}

function printCommit(result) {
  process.stdout.write([
    `Committed: ${result.path}`,
    `Risk: ${result.risk.level} (${result.risk.reason})`,
    `SHA-256: ${result.sha256After}`,
    `Snapshot created: ${result.snapshotCreated ? 'yes' : 'no'}`,
    `Committed at: ${result.committedAt}`,
    '',
  ].join('\n'));
}

function printDoctor(info) {
  process.stdout.write([
    `AgentSafeFS ${info.version}`,
    `Mode: ${info.standalone ? 'standalone executable' : 'Node.js CLI'}`,
    `Platform: ${info.platform} ${info.arch}`,
    `Node runtime: ${info.node}`,
    `Root: ${info.root}`,
    `Config: ${info.configPath ?? '(none)'}`,
    'Status: OK',
    '',
  ].join('\n'));
}

function printHelp() {
  process.stdout.write(`AgentSafeFS ${CLI_VERSION}\n\n` +
`Guarded filesystem writes for AI agents, coding assistants, MCP tools, and automation.\n\n` +
`Usage:\n` +
`  agentsafefs plan  --target <path> (--from <file> | --text <text> | --stdin) [options]\n` +
`  agentsafefs write --target <path> (--from <file> | --text <text> | --stdin) [options]\n` +
`  agentsafefs doctor [options]\n` +
`  agentsafefs --version\n\n` +
`Commands:\n` +
`  plan      Validate and classify a proposed write without changing disk.\n` +
`  write     Propose, revalidate, commit, verify, and optionally audit one write.\n` +
`  doctor    Validate configuration/root and show runtime information.\n\n` +
`Options:\n` +
`  -t, --target <path>     Target path inside the configured root.\n` +
`  -f, --from <file>       Read replacement bytes from a file.\n` +
`      --text <text>       Use UTF-8 text supplied on the command line.\n` +
`      --stdin             Read replacement bytes from standard input.\n` +
`  -a, --approve <path>    Exact target confirmation for approval-required writes.\n` +
`  -r, --root <dir>        Workspace root (overrides config).\n` +
`  -c, --config <file>     Explicit JSON config file (never auto-loaded).\n` +
`      --json              Emit machine-readable JSON.\n` +
`  -h, --help              Show help.\n` +
`  -V, --version           Show version.\n\n` +
`Safety:\n` +
`  Higher-risk writes fail closed unless --approve resolves to the exact same target.\n` +
`  The plan command never mutates the target. Rollback state is intentionally not persisted\n` +
`  across CLI invocations; use the library API when same-process rollback is required.\n`);
}

function exitCodeFor(error) {
  const code = error?.code ?? '';
  if (code === 'APPROVAL_REQUIRED') return 4;
  if (code === 'POLICY_DENIED' || code.startsWith('PATH_')) return 3;
  if (code.startsWith('CONFLICT_') || code.includes('VERIFY') || code.includes('INTEGRITY') || code.includes('RECOVERY')) return 5;
  if (code.startsWith('CLI_') || code.startsWith('CONFIG_') || code.startsWith('ROOT_') || code === 'CONTENT_INVALID' || code.startsWith('RISK_')) return 2;
  return 1;
}

function serializeError(error) {
  return {
    code: error?.code ?? 'UNEXPECTED_ERROR',
    message: error instanceof Error ? error.message : String(error),
    details: error?.details ?? null,
  };
}

function printError(error, jsonMode) {
  const payload = serializeError(error);
  if (jsonMode) {
    process.stderr.write(`${JSON.stringify({ ok: false, error: payload }, null, 2)}\n`);
    return;
  }

  process.stderr.write(`AgentSafeFS error [${payload.code}]: ${payload.message}\n`);
  if (payload.details !== null) process.stderr.write(`Details: ${JSON.stringify(payload.details)}\n`);
  if (payload.code === 'APPROVAL_REQUIRED' && payload.details?.expectedPath) {
    process.stderr.write(`Re-run with: --approve "${payload.details.expectedPath}"\n`);
  }
}

function runCli(argv = process.argv.slice(2), { cwd = process.cwd() } = {}) {
  let jsonMode = argv.includes('--json');
  try {
    const { command, options } = parseArgv(argv);
    jsonMode = Boolean(options.json);

    if (options.version || command === 'version') {
      if (command && command !== 'version') usageError('--version may not be combined with a command');
      process.stdout.write(`${CLI_VERSION}\n`);
      return 0;
    }

    if (options.help || command === 'help' || command === null) {
      printHelp();
      return 0;
    }

    if (!['plan', 'write', 'doctor'].includes(command)) usageError(`Unknown command: ${command}`);
    assertOptionsAllowed(command, options);

    const resolved = resolveAgentOptions(cwd, options);
    const safeFs = new AgentSafeFS(resolved.agentOptions);

    if (command === 'doctor') {
      const info = {
        version: CLI_VERSION,
        standalone: isSea(),
        platform: process.platform,
        arch: process.arch,
        node: process.version,
        root: resolved.agentOptions.root,
        configPath: resolved.configPath,
      };
      if (jsonMode) printJson({ ok: true, action: 'doctor', ...info });
      else printDoctor(info);
      return 0;
    }

    const target = requireTarget(options);
    const input = readContent(cwd, options);
    const proposal = safeFs.proposeWrite({ path: target, content: input.content });

    if (command === 'plan') {
      if (jsonMode) printJson({ ok: true, action: 'plan', source: input.source, proposal: jsonSafe(proposal) });
      else printProposal(proposal);
      return 0;
    }

    const result = safeFs.commit(proposal.operationId, { confirmedPath: options.approve ?? null });
    if (jsonMode) printJson({ ok: true, action: 'write', source: input.source, proposal: jsonSafe(proposal), result: jsonSafe(result) });
    else printCommit(result);
    return 0;
  } catch (error) {
    if (!(error instanceof AgentSafeFSError) && !(error instanceof CliError)) {
      const wrapped = new CliError('UNEXPECTED_ERROR', error instanceof Error ? error.message : String(error));
      printError(wrapped, jsonMode);
      return 1;
    }
    printError(error, jsonMode);
    return exitCodeFor(error);
  }
}

process.exitCode = runCli();
