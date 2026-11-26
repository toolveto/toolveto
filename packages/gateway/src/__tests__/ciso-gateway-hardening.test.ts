import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createGatewayServer } from '../index.js';

describe('CISO PATCH-12 & PATCH-13: Gateway Auth Failure Lockout, Per-IP Rate Limit & Prefix Route Isolation', () => {
  it('enforces per-IP auth failure lockout (429) on /mcp and request rate limit (429) on /health', async () => {
    const prevAuthMax = process.env.TOOLVETO_AUTH_MAX_FAILURES_PER_MIN;
    const prevReqMax = process.env.TOOLVETO_RATE_LIMIT_PER_MIN;
    const prevNodeEnv = process.env.NODE_ENV;
    process.env.TOOLVETO_AUTH_MAX_FAILURES_PER_MIN = '3';
    process.env.TOOLVETO_RATE_LIMIT_PER_MIN = '12';
    process.env.NODE_ENV = 'test';

    const upstream = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { tools: [] } }));
    });
    await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', () => resolve()));
    const upAddr = upstream.address() as any;

    const gw = createGatewayServer({
      port: 0,
      auth: { type: 'bearer', secret: 'gateway_test_secret_at_least_16_chars' },
      upstreams: {
        default: { name: 'default', url: `http://127.0.0.1:${upAddr.port}/mcp`, policy: 'standard' },
      },
    });
    await new Promise<void>((resolve) => gw.listen(0, '127.0.0.1', () => resolve()));
    const gwAddr = gw.address() as any;
    const gwUrl = `http://127.0.0.1:${gwAddr.port}`;

    try {
      // 3 invalid auth attempts return 401
      for (let i = 0; i < 3; i += 1) {
        const res = await fetch(`${gwUrl}/mcp`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: 'Bearer wrong-token' },
          body: JSON.stringify({ jsonrpc: '2.0', id: i, method: 'tools/list' }),
        });
        assert.equal(res.status, 401);
      }

      // 4th attempt is locked out with 429 even with valid secret
      const locked = await fetch(`${gwUrl}/mcp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer gateway_test_secret_at_least_16_chars' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 99, method: 'tools/list' }),
      });
      assert.equal(locked.status, 429);

      // Exceeding REQ_MAX_PER_IP_PER_MIN triggers 429 on /health
      let sawHealth429 = false;
      for (let i = 0; i < 15; i += 1) {
        const r = await fetch(`${gwUrl}/health`);
        if (r.status === 429) {
          sawHealth429 = true;
          break;
        }
      }
      assert.equal(sawHealth429, true, 'Expected /health to enforce per-IP sliding-window rate limit (429)');
    } finally {
      await new Promise<void>((resolve) => gw.close(() => resolve()));
      await new Promise<void>((resolve) => upstream.close(() => resolve()));
      if (prevAuthMax === undefined) delete process.env.TOOLVETO_AUTH_MAX_FAILURES_PER_MIN;
      else process.env.TOOLVETO_AUTH_MAX_FAILURES_PER_MIN = prevAuthMax;
      if (prevReqMax === undefined) delete process.env.TOOLVETO_RATE_LIMIT_PER_MIN;
      else process.env.TOOLVETO_RATE_LIMIT_PER_MIN = prevReqMax;
      if (prevNodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = prevNodeEnv;
    }
  });
});
