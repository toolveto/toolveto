import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import * as path from 'node:path';
import * as fs from 'node:fs';
import { StdioMcpClient } from '../transports/stdio.js';
import { runSuite } from '../evaluator.js';
import { formatTerminalReport } from '../reporters/terminal.js';
import { renderPRComment } from '../reporters/github-pr-comment.js';

function getFixturesDir(): string {
  const startDirs = [
    typeof __dirname !== 'undefined' ? __dirname : '',
    process.cwd(),
  ].filter(Boolean);

  for (const start of startDirs) {
    let cur = start;
    while (cur && cur !== path.dirname(cur)) {
      const candidate = path.join(cur, 'fixtures');
      if (fs.existsSync(candidate) && fs.existsSync(path.join(candidate, 'good-server'))) {
        return candidate;
      }
      cur = path.dirname(cur);
    }
  }
  throw new Error('Fixtures directory not found');
}

describe('E2E Stdio Fixture Servers Test Suite', () => {
  const fixturesDir = getFixturesDir();
  const goodServerScript = path.join(fixturesDir, 'good-server/index.js');
  const badServerScript = path.join(fixturesDir, 'bad-server/index.js');

  it('should evaluate good-server over stdio: score >= 80, 0 fatal vetoes, exit 0 ready', async () => {
    const client = new StdioMcpClient({
      command: process.execPath,
      args: [goodServerScript],
      timeoutMs: 15000,
    });

    try {
      await client.connect();
      const tools = await client.listTools();
      assert.ok(tools.length >= 3, `Expected at least 3 tools, got ${tools.length}`);

      const summary = await runSuite('fixtures/good-server', tools, { client });

      assert.strictEqual(summary.fatalVetoTriggered, false, 'Good server must trigger zero fatal vetoes');
      assert.strictEqual(summary.phi, 1.0, 'Good server phi multiplier must be 1.0');
      assert.ok(summary.score >= 80, `Good server score must be >= 80 (Gold/Platinum), got ${summary.score}`);
      assert.ok(['Gold', 'Platinum'].includes(summary.tier));
      assert.strictEqual(summary.failed, 0, `Expected 0 check failures on good server, got ${summary.failed}`);

      const terminalOutput = formatTerminalReport(summary);
      assert.ok(terminalOutput.includes('MERGE READY'));
      assert.ok(terminalOutput.includes('ToolVeto Score'));

      const prComment = renderPRComment(summary);
      assert.ok(prComment.includes('All checks passed'));
    } finally {
      await client.close();
    }
  });

  it('should evaluate bad-server over stdio: catches 3 wrecks, triggers fatal veto, provides diffs', async () => {
    const client = new StdioMcpClient({
      command: process.execPath,
      args: [badServerScript],
      timeoutMs: 15000,
    });

    try {
      await client.connect();
      const tools = await client.listTools();
      assert.ok(tools.length >= 3);

      const summary = await runSuite('fixtures/bad-server', tools, { client });

      // Fatal veto must be triggered
      assert.strictEqual(summary.fatalVetoTriggered, true, 'Bad server must trigger fatal veto');
      assert.ok(summary.phi <= 0.5, `Phi multiplier must be penalized (<= 0.5), got ${summary.phi}`);
      assert.strictEqual(summary.tier, 'Failed', 'Bad server tier must be Failed');
      assert.ok(summary.failed >= 3, `Expected at least 3 check failures, got ${summary.failed}`);

      // Verify Wreck 1: Idempotency failure on create_payment
      const idempFail = summary.results.find(
        (r) => r.tool === 'create_payment' && r.checkId === 'TC-IDEMP-001' && r.status === 'FAIL'
      );
      assert.ok(idempFail, 'Must catch TC-IDEMP-001 on create_payment');
      assert.ok(idempFail.fix, 'Must include fix diff for create_payment');
      assert.ok(idempFail.fix.diffs.some((d) => d.language === 'typescript-zod'));

      // Verify Wreck 2: Error loop / stack trace on update_appointment
      const errFail = summary.results.find(
        (r) => r.tool === 'update_appointment' && r.status === 'FAIL'
      );
      assert.ok(errFail, 'Must catch error failure on update_appointment');

      // Verify Wreck 3: Context Bomb on list_invoices
      const contextFail = summary.results.find(
        (r) => r.tool === 'list_invoices' && (r.checkId === 'TC-CTX-001' || r.checkId === 'TC-SCHEMA-001') && r.status === 'FAIL'
      );
      assert.ok(contextFail, 'Must catch context bomb / unpaginated failure on list_invoices');

      // Verify terminal report contains block message
      const terminalOutput = formatTerminalReport(summary);
      assert.ok(terminalOutput.includes('MERGE BLOCKED'));
      assert.ok(terminalOutput.includes('FATAL VETO TRIGGERED'));
      assert.ok(terminalOutput.includes('toolveto fix --apply'));

      // Verify PR comment contains blocked warning
      const prComment = renderPRComment(summary);
      assert.ok(prComment.includes('This PR is blocked'));
    } finally {
      await client.close();
    }
  });
});
