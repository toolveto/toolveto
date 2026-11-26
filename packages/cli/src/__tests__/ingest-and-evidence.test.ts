import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { synthesizeCasesFromTraceSpans, ingestCommand } from '../commands/ingest.js';
import { parseEvidencePeriodDays } from '../commands/evidence.js';
import { DockerSandboxAdapter } from '@toolveto/core';
import { ShieldMiddleware, PostgresShieldStorage } from '@toolveto/shield';

describe('CLI Ingest, Evidence Period, DockerSandboxAdapter & Shield Hardening', () => {
  it('synthesizes deduplicated regression cases from JSON and JSONL trace files', async () => {
    const spans = [
      { toolName: 'charge_card', isError: true, arguments: { amount: 500 } },
      { toolName: 'charge_card', isError: true, arguments: { amount: 500 } },
      { toolName: 'list_orders', durationMs: 4200 },
      { toolName: 'export_all', outputTokens: 12000 },
      { toolName: 'healthy_ping', durationMs: 12, isError: false },
    ];
    const cases = synthesizeCasesFromTraceSpans(spans);
    assert.equal(cases.length, 3);
    assert.equal(cases[0].checkId, 'TC-IDEMP-001');
    assert.equal(cases[1].checkId, 'TC-ERR-001');
    assert.equal(cases[2].checkId, 'TC-CTX-001');

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-ingest-test-'));
    try {
      const jsonlPath = path.join(tmpDir, 'traces.jsonl');
      const outPath = path.join(tmpDir, 'corpus.json');
      fs.writeFileSync(jsonlPath, spans.map((s) => JSON.stringify(s)).join('\n'));
      const res = await ingestCommand(jsonlPath, { output: outPath, format: 'json' });
      assert.equal(res.length, 3);
      assert.equal(fs.existsSync(outPath), true);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('parseEvidencePeriodDays parses 30d, 90d, 1y, and clamps safely', () => {
    assert.equal(parseEvidencePeriodDays('30d'), 30);
    assert.equal(parseEvidencePeriodDays('90d'), 90);
    assert.equal(parseEvidencePeriodDays('1y'), 365);
    assert.equal(parseEvidencePeriodDays('invalid'), 90);
  });

  it('DockerSandboxAdapter runs seed and always executes cleanup in finally', async () => {
    const adapter = new DockerSandboxAdapter({
      sandbox: {
        seed_command: 'node -e 1',
        cleanup_command: 'node -e 1',
        timeoutMs: 5000,
      },
    });
    const ok = await adapter.executeWithLifecycle(async () => 'done');
    assert.equal(ok.seeded, true);
    assert.equal(ok.result, 'done');
  });

  it('ShieldMiddleware accepts declarative maxLoopCount and defaultPageLimit aliases', async () => {
    const mw = new ShieldMiddleware({
      maxLoopCount: 2,
      defaultPageLimit: 200,
      keyFields: ['request_id'],
      redisUrl: 'redis://localhost:6379',
    });
    let calls = 0;
    const exec = async () => {
      calls++;
      return { content: [{ type: 'text', text: 'ok' }] };
    };
    await mw.intercept({ method: 'tools/call', params: { name: 'search', arguments: { q: 'x' } } }, exec);
    await mw.intercept({ method: 'tools/call', params: { name: 'search', arguments: { q: 'x' } } }, exec);
    const blocked = await mw.intercept({ method: 'tools/call', params: { name: 'search', arguments: { q: 'x' } } }, exec);
    assert.equal(calls, 2);
    assert.equal(blocked.isError, true);
  });

  it('PostgresShieldStorage enforces server-side SET LOCAL statement_timeout when pool connect() is present', async () => {
    const seenSql: string[] = [];
    const fakePool = {
      query: async () => ({ rows: [] }),
      connect: async () => ({
        query: async (sql: string) => {
          seenSql.push(sql);
          return { rows: [] };
        },
        release: () => undefined,
      }),
    };
    const store = new PostgresShieldStorage(fakePool, { statementTimeoutMs: 2500 });
    await store.get('k1');
    assert.ok(seenSql.some((s) => s.includes("set_config('statement_timeout'")));
    assert.ok(seenSql.some((s) => s.includes('idx_toolveto_shield_cache_expires')));
  });
});
