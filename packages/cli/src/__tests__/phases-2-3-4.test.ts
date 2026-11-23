import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import { discoverCommand } from '../commands/discover.js';
import {
  generateWeaveProofCedarPolicy,
  generateWeaveProofGenomeManifest,
} from '../commands/export-policy.js';
import { evaluateOrgCatalogAccess, type McpToolDefinition } from '@toolveto/core';

describe('Phases 2–4 CLI: Zero-Secret Shadow MCP Discovery, Catalog Enforcement & WeaveProof Taint Export', () => {
  it('Phase 3: discover --upload flags plaintext secrets as boolean ONLY and never transmits raw secret values', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-discover-'));
    const cursorCfg = path.join(tmpDir, 'mcp.json');
    const policyPath = path.join(tmpDir, 'policy.json');

    const secretStripe = ['sk', 'live', '51SuperSecretKeyNeverTransmit999'].join('_');
    const secretGh = ['ghp', '1234567890abcdef1234567890abcdef'].join('_');

    fs.writeFileSync(
      cursorCfg,
      JSON.stringify({
        mcpServers: {
          'github-shadow': {
            command: 'npx',
            args: ['-y', 'github-mcp-server@latest', `--token=${secretGh}`],
            env: { GITHUB_TOKEN: secretGh },
          },
          'stripe-shadow': {
            command: 'npx',
            args: ['-y', '@stripe/agent-toolkit@latest'],
            env: { STRIPE_API_KEY: secretStripe },
          },
          'postgres-shadow': {
            command: 'npx',
            args: ['-y', '@supabase/mcp-server-supabase@0.4.1'],
            env: { DB_URL: '${SUPABASE_DB_URL}' },
          },
        },
      }),
      'utf8'
    );

    fs.writeFileSync(
      policyPath,
      JSON.stringify({
        schemaVersion: 'toolveto-org-catalog/v1',
        generatedAt: Date.now(),
        graceWindowHours: 72,
        entries: [{ serverPattern: 'stripe-shadow', status: 'QUARANTINED', reason: 'Unpinned @latest' }],
      }),
      'utf8'
    );

    let receivedUploadRaw = '';
    const mockCloud = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        receivedUploadRaw = body;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, ingested: 3 }));
      });
    });

    await new Promise<void>((resolve) => mockCloud.listen(0, '127.0.0.1', () => resolve()));
    const port = (mockCloud.address() as any).port;
    const prevExit = process.exitCode;

    try {
      const report = await discoverCommand({
        configPaths: [{ ideClient: 'cursor-project', filePath: cursorCfg }],
        json: true,
        upload: true,
        enforceCatalog: true,
        policyFile: policyPath,
        apiUrl: `http://127.0.0.1:${port}`,
        token: 'tv_enroll_test_token_12345',
      });

      assert.equal(report.uploaded, true);
      assert.equal(report.servers.length, 3);
      assert.equal(report.summary.plaintextSecretCount, 2);
      assert.equal(report.summary.quarantinedCount, 1);
      assert.equal(report.summary.lethalTrifectaExposed, true);
      assert.match(report.hostHmac, /^HOST_[0-9a-f]{24}$/);
      assert.equal(process.exitCode, 1, 'Catalog quarantine must set exitCode = 1');

      // MATHEMATICAL ZERO-SECRET PROOF: neither raw secret may appear anywhere in uploaded payload
      assert.ok(receivedUploadRaw.length > 0, 'Expected upload payload');
      assert.equal(receivedUploadRaw.includes(secretStripe), false, 'Stripe secret MUST NEVER be uploaded');
      assert.equal(receivedUploadRaw.includes(secretGh), false, 'GitHub token MUST NEVER be uploaded');
      assert.equal(receivedUploadRaw.includes(os.hostname()), false, 'Raw hostname MUST NEVER be uploaded');
    } finally {
      process.exitCode = prevExit;
      await new Promise<void>((resolve) => mockCloud.close(() => resolve()));
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('Phase 4: export-policy --format weaveproof & weaveproof-genome emit @taint_source and session_taint guards', () => {
    const tools: McpToolDefinition[] = [
      {
        name: 'get_issue',
        description: 'Fetch external GitHub issue text',
        isMutation: false,
        readOnlyHint: true,
        openWorldHint: true,
        inputSchema: { type: 'object', properties: { issue_id: { type: 'string' } } },
      },
      {
        name: 'query_sql',
        description: 'Query private postgres database',
        isMutation: false,
        readOnlyHint: true,
        inputSchema: { type: 'object', properties: { sql: { type: 'string' } } },
      },
      {
        name: 'slack_post_message',
        description: 'Send external Slack message',
        isMutation: true,
        openWorldHint: true,
        inputSchema: { type: 'object', properties: { channel: { type: 'string' }, text: { type: 'string' } } },
      },
    ];

    const cedar = generateWeaveProofCedarPolicy(tools);
    assert.ok(cedar.includes('@taint_source("UNTRUSTED_EXTERNAL_INGEST")'));
    assert.ok(cedar.includes('!context.session_taint.contains("UNTRUSTED_EXTERNAL_INGEST")'));

    const genome = JSON.parse(generateWeaveProofGenomeManifest(tools));
    assert.equal(genome.schemaVersion, 'weaveproof-genome/v1');
    assert.equal(genome.toxicFlowSummary.lethalTrifectaDetected, true);
    const ingestEntry = genome.pinnedTools.find((t: any) => t.toolName === 'get_issue');
    const egressEntry = genome.pinnedTools.find((t: any) => t.toolName === 'slack_post_message');
    assert.equal(ingestEntry.taintSourceLabel, 'UNTRUSTED_EXTERNAL_INGEST');
    assert.equal(egressEntry.blockWhenSessionTainted, true);
  });

  it('Phase 3: Org Catalog Kill Switch supports leading, interior, and trailing wildcard globs with -32004 fail-closed precedence', () => {
    const policy = {
      schemaVersion: 'toolveto-org-catalog/v1' as const,
      generatedAt: Date.now(),
      graceWindowHours: 72,
      entries: [
        { serverPattern: '*stripe*', status: 'QUARANTINED' as const, reason: 'Unpinned @latest' },
        { serverPattern: '@modelcontextprotocol/*filesystem*', status: 'BLOCKED' as const, reason: 'Restricted host FS' },
        { serverPattern: 'github/*', status: 'APPROVED' as const },
      ],
    };

    const stripeDecision = evaluateOrgCatalogAccess(policy, '@stripe/mcp');
    assert.equal(stripeDecision.allowed, false);
    assert.equal(stripeDecision.code, -32004);
    assert.equal(stripeDecision.status, 'QUARANTINED');

    const fsDecision = evaluateOrgCatalogAccess(policy, '@modelcontextprotocol/server-filesystem');
    assert.equal(fsDecision.allowed, false);
    assert.equal(fsDecision.code, -32004);
    assert.equal(fsDecision.status, 'BLOCKED');

    const ghDecision = evaluateOrgCatalogAccess(policy, 'github/github-mcp-server');
    assert.equal(ghDecision.allowed, true);
    assert.equal(ghDecision.status, 'APPROVED');
  });
});
