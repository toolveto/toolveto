import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as http from 'node:http';
import { createGatewayServer } from '../index.js';

describe('Phase 3: ToolVeto Gateway Enterprise Approved Catalog Kill Switch (-32004)', () => {
  it('blocks calls to QUARANTINED servers with -32004 ORG_CATALOG_QUARANTINED without contacting upstream, while allowing APPROVED servers', async () => {
    let upstreamHits = 0;
    const upstream = http.createServer((req, res) => {
      upstreamHits += 1;
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        const parsed = JSON.parse(body || '{}');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            id: parsed.id ?? 1,
            result: { content: [{ type: 'text', text: JSON.stringify({ ok: true }) }] },
          })
        );
      });
    });

    await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', () => resolve()));
    const upPort = (upstream.address() as any).port;

    const gateway = createGatewayServer({
      allowLocal: true,
      auth: { type: 'none' },
      catalogPolicy: {
        schemaVersion: 'toolveto-org-catalog/v1',
        tenantId: 'cus_enterprise_1',
        generatedAt: Date.now(),
        graceWindowHours: 72,
        entries: [
          {
            serverPattern: 'rogue-slack',
            status: 'QUARANTINED',
            reason: 'Rug-pull detected on v1.4.2',
          },
          {
            serverPattern: 'approved-billing',
            status: 'APPROVED',
            reason: 'Signed & pinned',
          },
        ],
      },
      upstreams: {
        'rogue-slack': {
          name: 'rogue-slack',
          url: `http://127.0.0.1:${upPort}/mcp`,
          pathPrefix: '/mcp/rogue-slack',
          allowLocal: true,
        },
        'approved-billing': {
          name: 'approved-billing',
          url: `http://127.0.0.1:${upPort}/mcp`,
          pathPrefix: '/mcp/approved-billing',
          allowLocal: true,
        },
      },
    });

    await new Promise<void>((resolve) => gateway.listen(0, '127.0.0.1', () => resolve()));
    const gwPort = (gateway.address() as any).port;

    try {
      // 1. Quarantined server MUST be killed immediately with -32004 and ZERO upstream hits
      const blockedRes = await fetch(`http://127.0.0.1:${gwPort}/mcp/rogue-slack`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { name: 'post_message', arguments: { text: 'hello' } },
        }),
      });
      assert.equal(blockedRes.status, 200);
      assert.equal(blockedRes.headers.get('x-toolveto-catalog-status'), 'QUARANTINED');
      const blockedJson: any = await blockedRes.json();
      assert.equal(blockedJson.error?.code, -32004);
      assert.match(blockedJson.error?.message || '', /ORG_CATALOG_QUARANTINED/);
      assert.equal(upstreamHits, 0, 'Quarantined server call must NEVER reach upstream');

      // 2. Approved server proceeds cleanly to upstream
      const okRes = await fetch(`http://127.0.0.1:${gwPort}/mcp/approved-billing`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 2,
          method: 'tools/call',
          params: { name: 'get_invoice', arguments: { id: 'inv_1' } },
        }),
      });
      assert.equal(okRes.status, 200);
      const okJson: any = await okRes.json();
      assert.equal(okJson.error, undefined);
      assert.equal(upstreamHits, 1);
    } finally {
      await new Promise<void>((resolve) => gateway.close(() => resolve()));
      await new Promise<void>((resolve) => upstream.close(() => resolve()));
    }
  });
});
