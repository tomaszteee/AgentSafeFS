import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { AgentSafeFS } from '../src/index.mjs';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentsafefs-example-'));

try {
  const safeFs = new AgentSafeFS({
    root,
    auditPath: '.agentsafefs/audit.jsonl',
  });

  const proposal = safeFs.proposeWrite({
    path: 'example-output.txt',
    content: 'written through AgentSafeFS\n',
  });

  console.log('proposal', proposal);

  const result = safeFs.commit(proposal.operationId, {
    confirmedPath: proposal.risk.requiresApproval ? proposal.path : null,
  });

  console.log('commit', result);
  console.log('content', fs.readFileSync(path.join(root, 'example-output.txt'), 'utf8'));
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}
