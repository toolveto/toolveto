import { describe, it, before, after } from 'node:test';
import * as assert from 'node:assert';
import http from 'http';
import { createGatewayServer } from '../index.js';

describe('ToolVeto Gateway Reverse Proxy', () => {
  let mockUpstream: http.Server;
  let gatewayServer: http.Server;
  let upstreamPort: number;
  let gatewayPort: number;
  let upstreamCalls = 0;

  before(async () => {
    // 1. Start mock upstream MCP server
    mockUpstream = http.createServer((req, res) => {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        upstreamCalls++;
        const rpc = JSON.parse(body);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          jsonrpc: '2.0',
          id: rpc.id,
          result: {
            content: [{ type: 'text', text: `Upstream result for ${rpc.params?.name} (#${upstreamCalls})` }]
          }
        }));
      });
    });

    await new Promise<void>((resolve) => {
      mockUpstream.listen(0, () => {
        upstreamPort = (mockUpstream.address() as any).port;
        resolve();
      });
    });

    // 2. Start Gateway Server pointing to mock upstream
    gatewayServer = createGatewayServer({
      port: 0,
      upstreamUrl: `http://localhost:${upstreamPort}/mcp`,
      shieldOptions: {
        idempotency: true,
        loopLimit: { count: 3, windowMs: 10000 },
        tokenBudget: 500,
      }
    });

    await new Promise<void>((resolve) => {
      gatewayServer.listen(0, () => {
        gatewayPort = (gatewayServer.address() as any).port;
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise<void>((resolve) => mockUpstream.close(() => resolve()));
    await new Promise<void>((resolve) => gatewayServer.close(() => resolve()));
  });

  it('should respond healthy on GET /health with live metrics', async () => {
    const res = await fetch(`http://localhost:${gatewayPort}/health`);
    assert.strictEqual(res.status, 200);
    const data = await res.json() as any;
    assert.strictEqual(data.status, 'healthy');
    assert.strictEqual(data.service, 'toolveto-gateway');
    assert.ok(data.metrics);
  });

  it('should forward tools/call to upstream and deduplicate identical idempotency keys', async () => {
    const initialCalls = upstreamCalls;

    const payload = {
      jsonrpc: '2.0',
      id: 'req_1',
      method: 'tools/call',
      params: {
        name: 'create_order',
        arguments: { item: 'widget', idempotency_key: 'idemp_order_999' }
      }
    };

    // 1st request: forwards to upstream
    const res1 = await fetch(`http://localhost:${gatewayPort}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    assert.strictEqual(res1.status, 200);
    const data1 = await res1.json() as any;
    assert.ok(data1.result.content[0].text.includes('Upstream result for create_order'));
    assert.strictEqual(upstreamCalls, initialCalls + 1);

    // 2nd request with identical idempotency_key: Shield intercepts & serves cached response without hitting upstream!
    const res2 = await fetch(`http://localhost:${gatewayPort}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    assert.strictEqual(res2.status, 200);
    const data2 = await res2.json() as any;
    assert.strictEqual(data2.result.content[0].text, data1.result.content[0].text);
    assert.strictEqual(upstreamCalls, initialCalls + 1, 'Upstream must NOT receive duplicate request');
  });

  it('should break runaway retry loops when limit exceeded', async () => {
    const payload = {
      jsonrpc: '2.0',
      id: 'req_loop',
      method: 'tools/call',
      params: {
        name: 'looping_tool',
        arguments: { arg: 'bad_value' }
      }
    };

    // Fire 3 calls (allowed under count: 3)
    await fetch(`http://localhost:${gatewayPort}/mcp`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    await fetch(`http://localhost:${gatewayPort}/mcp`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    await fetch(`http://localhost:${gatewayPort}/mcp`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });

    // 4th call: must be blocked by Shield loop-breaker
    const blockedRes = await fetch(`http://localhost:${gatewayPort}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const blockedData = await blockedRes.json() as any;
    assert.strictEqual(blockedData.result.isError, true);
    assert.ok(blockedData.result.content[0].text.includes('Loop detected'));
  });
});
