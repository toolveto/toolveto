import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import http from 'node:http';
import {
  createGatewayServer,
  parseOrCreateGatewayTrace,
  logGatewayJson,
} from '../index.js';

describe('Gateway Distributed Tracing, Security Headers & Structured Logging', () => {
  it('parseOrCreateGatewayTrace preserves valid W3C traceparent and regenerates invalid ones', () => {
    const validTp = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';
    const preserved = parseOrCreateGatewayTrace({
      'x-request-id': 'req_abc_123',
      traceparent: validTp,
    });
    assert.equal(preserved.requestId, 'req_abc_123');
    assert.equal(preserved.traceId, '4bf92f3577b34da6a3ce929d0e0e4736');
    assert.match(preserved.traceparent, /^00-4bf92f3577b34da6a3ce929d0e0e4736-[0-9a-f]{16}-01$/);

    const regen = parseOrCreateGatewayTrace({
      traceparent: '00-00000000000000000000000000000000-0000000000000000-01',
    });
    assert.notEqual(regen.traceId, '00000000000000000000000000000000');
    assert.ok(regen.requestId.startsWith('gw_'));
  });

  it('echoes X-Request-Id, Traceparent, and defensive security headers and forwards traceparent upstream', async () => {
    let upstreamTraceparent = '';
    let upstreamReqId = '';
    const upstream = http.createServer((req, res) => {
      upstreamTraceparent = String(req.headers['traceparent'] || '');
      upstreamReqId = String(req.headers['x-request-id'] || '');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { content: [{ type: 'text', text: 'pong' }] } }));
    });
    await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', () => resolve()));
    const upstreamPort = (upstream.address() as any).port;

    const gw = createGatewayServer({
      upstreams: {
        default: {
          name: 'default',
          url: `http://127.0.0.1:${upstreamPort}/mcp`,
          allowLocal: true,
        },
      },
    });
    await new Promise<void>((resolve) => gw.listen(0, '127.0.0.1', () => resolve()));
    const gwPort = (gw.address() as any).port;

    try {
      const healthRes = await fetch(`http://127.0.0.1:${gwPort}/health`, {
        headers: {
          'x-request-id': 'gw_test_corr_1',
          traceparent: '00-11111111111111111111111111111111-2222222222222222-01',
        },
      });
      assert.equal(healthRes.status, 200);
      assert.equal(healthRes.headers.get('x-request-id'), 'gw_test_corr_1');
      assert.match(healthRes.headers.get('traceparent') || '', /^00-11111111111111111111111111111111-/);
      assert.equal(healthRes.headers.get('x-content-type-options'), 'nosniff');
      assert.equal(healthRes.headers.get('x-frame-options'), 'DENY');
      assert.equal(healthRes.headers.get('cache-control'), 'no-store');
      assert.match(healthRes.headers.get('content-security-policy') || '', /default-src 'none'/);

      const mcpRes = await fetch(`http://127.0.0.1:${gwPort}/mcp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-request-id': 'gw_mcp_corr_2',
          traceparent: '00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { name: 'ping', arguments: {} },
        }),
      });
      assert.equal(mcpRes.status, 200);
      assert.equal(upstreamReqId, 'gw_mcp_corr_2');
      assert.match(upstreamTraceparent, /^00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-[0-9a-f]{16}-01$/);

      logGatewayJson('debug', 'suppressed_in_test');
    } finally {
      await new Promise<void>((resolve) => gw.close(() => resolve()));
      await new Promise<void>((resolve) => upstream.close(() => resolve()));
    }
  });
});
