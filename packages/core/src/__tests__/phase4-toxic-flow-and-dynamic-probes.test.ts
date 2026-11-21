import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as http from 'node:http';
import {
  analyzeToxicFlow,
  runToxicFlowCheck,
  runRealSocketCutCrashCommitCheck,
  runTriPhaseReadProbeCheck,
  evaluateJmesPath,
  InMemoryMcpClient,
  type McpToolDefinition,
} from '../index.js';

describe('Phase 4: Lethal Trifecta Toxic Flow & Real Dynamic Probes (PAT-01 & PAT-03)', () => {
  it('TC-TOXIC-001: detects cross-MCP Lethal Trifecta exfiltration chain and raises VETO_EXFIL', () => {
    const multiServerTools: Array<McpToolDefinition & { serverName?: string }> = [
      {
        serverName: 'github-mcp',
        name: 'get_issue',
        description: 'Fetch public GitHub issue comments and body from external contributors',
        isMutation: false,
        readOnlyHint: true,
        openWorldHint: true,
        inputSchema: { type: 'object', properties: { repo: { type: 'string' }, issue_number: { type: 'number' } } },
      },
      {
        serverName: 'postgres-prod',
        name: 'query_customer_sql',
        description: 'Run SQL query against internal customer billing database',
        isMutation: false,
        readOnlyHint: true,
        inputSchema: { type: 'object', properties: { sql: { type: 'string' } } },
      },
      {
        serverName: 'slack-workspace',
        name: 'slack_post_message',
        description: 'Send outbound message to external Slack channel or webhook',
        isMutation: true,
        openWorldHint: true,
        inputSchema: { type: 'object', properties: { channel: { type: 'string' }, text: { type: 'string' } } },
      },
    ];

    const analysis = analyzeToxicFlow(multiServerTools);
    assert.equal(analysis.lethalTrifectaDetected, true);
    assert.equal(analysis.riskLevel, 'CRITICAL');
    assert.ok(analysis.toxicPaths.length >= 1);
    assert.equal(analysis.toxicPaths[0]!.crossServer, true);

    const check = runToxicFlowCheck(multiServerTools);
    assert.equal(check.checkId, 'TC-TOXIC-001');
    assert.equal(check.status, 'FAIL');
    assert.equal(check.severity, 'CRITICAL');
    assert.equal(check.vetoClass, 'VETO_EXFIL');
    assert.ok(check.fix?.diffs[0]?.code.includes('@taint_source("UNTRUSTED_EXTERNAL_INGEST")'));

    // Passing when protected by explicit runtime taint boundary
    const guarded = runToxicFlowCheck(multiServerTools, { hasRuntimeTaintBoundary: true });
    assert.equal(guarded.status, 'PASS');
  });

  it('PAT-01: real TCP socket-cut proxy catches non-idempotent post-commit double-write and passes idempotent server', async () => {
    const paymentTool: McpToolDefinition = {
      name: 'create_payment',
      description: 'Charge card with idempotency key',
      isMutation: true,
      inputSchema: {
        type: 'object',
        properties: {
          amount: { type: 'number' },
          idempotency_key: { type: 'string' },
        },
        required: ['amount', 'idempotency_key'],
      },
    };

    // 1. Buggy non-idempotent HTTP MCP server (commits a brand new ID on every request!)
    let buggyCounter = 0;
    const buggyServer = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        buggyCounter += 1;
        const parsed = JSON.parse(body || '{}');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        // Delay body slightly so TCP proxy catches HTTP 200 headers mid-flight cleanly
        res.flushHeaders();
        setTimeout(() => {
          res.end(
            JSON.stringify({
              jsonrpc: '2.0',
              id: parsed.id ?? 1,
              result: {
                content: [{ type: 'text', text: JSON.stringify({ id: `pay_bug_${buggyCounter}`, status: 'charged' }) }],
              },
            })
          );
        }, 15);
      });
    });

    await new Promise<void>((resolve) => buggyServer.listen(0, '127.0.0.1', () => resolve()));
    const buggyPort = (buggyServer.address() as any).port;
    try {
      const failResult = await runRealSocketCutCrashCommitCheck(paymentTool, `http://127.0.0.1:${buggyPort}/mcp`, {
        backoffMs: 30,
        inspectStateCount: async () => buggyCounter,
      });
      assert.equal(failResult.status, 'FAIL');
      assert.equal(failResult.severity, 'CRITICAL');
      assert.equal(failResult.evidence.evidenceQuality, 'VERIFIED');
      assert.equal(failResult.evidence.details?.faultMode, 'real-tcp-socket-cut');
      assert.equal(failResult.evidence.details?.cutsExecuted, 1);
      assert.ok(buggyCounter >= 2, 'Buggy server must have executed duplicate post-commit mutations');
    } finally {
      await new Promise<void>((resolve) => buggyServer.close(() => resolve()));
    }

    // 2. Properly idempotent HTTP MCP server (deduplicates by idempotency_key)
    const idempStore = new Map<string, string>();
    const safeServer = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        const parsed = JSON.parse(body || '{}');
        const key = String(parsed?.params?.arguments?.idempotency_key || 'none');
        if (!idempStore.has(key)) {
          idempStore.set(key, `pay_safe_${idempStore.size + 1}`);
        }
        const entityId = idempStore.get(key)!;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.flushHeaders();
        setTimeout(() => {
          res.end(
            JSON.stringify({
              jsonrpc: '2.0',
              id: parsed.id ?? 1,
              result: {
                content: [{ type: 'text', text: JSON.stringify({ id: entityId, status: 'charged' }) }],
              },
            })
          );
        }, 15);
      });
    });

    await new Promise<void>((resolve) => safeServer.listen(0, '127.0.0.1', () => resolve()));
    const safePort = (safeServer.address() as any).port;
    try {
      const passResult = await runRealSocketCutCrashCommitCheck(paymentTool, `http://127.0.0.1:${safePort}/mcp`, {
        backoffMs: 30,
        inspectStateCount: async () => idempStore.size,
      });
      assert.equal(passResult.status, 'PASS');
      assert.equal(passResult.evidence.evidenceQuality, 'VERIFIED');
      assert.equal(passResult.evidence.details?.cutsExecuted, 1);
      assert.equal(idempStore.size, 1, 'Idempotent server must commit exactly once despite socket cut');
    } finally {
      await new Promise<void>((resolve) => safeServer.close(() => resolve()));
    }
  });

  it('PAT-03: live tri-phase read-probe catches silent 200-OK stub mock and verifies real stateful server with cleanup', async () => {
    assert.equal(evaluateJmesPath({ data: { items: [{ id: 'ord_99' }] } }, 'data.items[0].id'), 'ord_99');
    assert.equal(evaluateJmesPath({ result: { id: 'ord_77' } }, 'id || result.id'), 'ord_77');

    const tools: McpToolDefinition[] = [
      {
        name: 'create_order',
        isMutation: true,
        inputSchema: { type: 'object', properties: { note: { type: 'string' }, idempotency_key: { type: 'string' } } },
      },
      {
        name: 'get_order',
        isMutation: false,
        readOnlyHint: true,
        inputSchema: { type: 'object', properties: { order_id: { type: 'string' } } },
      },
      {
        name: 'delete_order',
        isMutation: true,
        destructiveHint: true,
        inputSchema: { type: 'object', properties: { order_id: { type: 'string' } } },
      },
    ];

    // 1. Silent 200-OK stubbed mock (claims success, never stores anything!)
    const mockClient = new InMemoryMcpClient(tools, async (toolName) => {
      if (toolName === 'create_order') {
        return { content: [{ type: 'text', text: JSON.stringify({ id: 'ord_phantom_1', ok: true }) }] };
      }
      return { content: [{ type: 'text', text: JSON.stringify({ error: 'not_found' }) }] };
    });

    const mockRes = await runTriPhaseReadProbeCheck(tools[0]!, tools, mockClient, {
      backoffScheduleMs: [5, 10],
    });
    assert.equal(mockRes.status, 'FAIL');
    assert.equal(mockRes.severity, 'CRITICAL');
    assert.equal(mockRes.vetoClass, 'VETO_DATALOSS');
    assert.equal(mockRes.evidence.evidenceQuality, 'VERIFIED');

    // 2. Real stateful server (persists write, visible on get_order, cleaned up by delete_order)
    const db = new Map<string, any>();
    let cleanupCalled = false;
    const statefulClient = new InMemoryMcpClient(tools, async (toolName, args) => {
      if (toolName === 'create_order') {
        const id = `ord_real_${db.size + 1}`;
        const rec = { id, ...args };
        db.set(id, rec);
        return { content: [{ type: 'text', text: JSON.stringify(rec) }] };
      }
      if (toolName === 'get_order') {
        const rec = db.get(String(args.order_id || args.id || ''));
        return { content: [{ type: 'text', text: JSON.stringify(rec || { error: 'not_found' }) }] };
      }
      if (toolName === 'delete_order') {
        cleanupCalled = true;
        db.delete(String(args.order_id || args.id || ''));
        return { content: [{ type: 'text', text: JSON.stringify({ deleted: true }) }] };
      }
      return { content: [{ type: 'text', text: '{}' }] };
    });

    const realRes = await runTriPhaseReadProbeCheck(tools[0]!, tools, statefulClient, {
      backoffScheduleMs: [5, 10],
    });
    assert.equal(realRes.status, 'PASS');
    assert.equal(realRes.evidence.evidenceQuality, 'VERIFIED');
    assert.equal(cleanupCalled, true, 'Companion delete cleanup must run automatically');
    assert.equal(db.size, 0, 'Synthetic probe entity must be cleaned up from state');
  });
});
