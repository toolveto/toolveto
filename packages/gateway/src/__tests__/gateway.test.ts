import { describe, it, before, after } from 'node:test';
import * as assert from 'node:assert';
import http from 'http';
import { createGatewayServer } from '../index.js';

describe('ToolVeto Gateway Reverse Proxy', () => {
  let mockDefaultUpstream: http.Server;
  let mockStripeUpstream: http.Server;
  let gatewayServer: http.Server;
  let defaultPort: number;
  let stripePort: number;
  let gatewayPort: number;
  let defaultCalls = 0;
  let stripeCalls = 0;

  before(async () => {
    // 1. Start mock default upstream MCP server
    mockDefaultUpstream = http.createServer((req, res) => {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        defaultCalls++;
        const rpc = JSON.parse(body);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          jsonrpc: '2.0',
          id: rpc.id,
          result: {
            content: [{ type: 'text', text: `Default result for ${rpc.params?.name} (#${defaultCalls})` }]
          }
        }));
      });
    });

    await new Promise<void>((resolve) => {
      mockDefaultUpstream.listen(0, () => {
        defaultPort = (mockDefaultUpstream.address() as any).port;
        resolve();
      });
    });

    // 2. Start mock stripe upstream MCP server
    mockStripeUpstream = http.createServer((req, res) => {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        stripeCalls++;
        const rpc = JSON.parse(body);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          jsonrpc: '2.0',
          id: rpc.id,
          result: {
            content: [{ type: 'text', text: `Stripe result for ${rpc.params?.name} (#${stripeCalls})` }]
          }
        }));
      });
    });

    await new Promise<void>((resolve) => {
      mockStripeUpstream.listen(0, () => {
        stripePort = (mockStripeUpstream.address() as any).port;
        resolve();
      });
    });

    // 3. Start Gateway Server with multi-upstream configuration and auth
    gatewayServer = createGatewayServer({
      port: 0,
      auth: {
        type: 'bearer',
        secret: 'test-gateway-secret-token',
      },
      upstreams: {
        stripe: {
          name: 'stripe',
          url: `http://localhost:${stripePort}/mcp`,
          pathPrefix: '/stripe',
          toolPrefix: 'stripe_',
          policy: 'strict',
          authHeader: 'Bearer sk_live_mock',
        },
        default: {
          name: 'default',
          url: `http://localhost:${defaultPort}/mcp`,
          policy: 'standard',
        },
      },
    });

    await new Promise<void>((resolve) => {
      gatewayServer.listen(0, () => {
        gatewayPort = (gatewayServer.address() as any).port;
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise<void>((resolve) => mockDefaultUpstream.close(() => resolve()));
    await new Promise<void>((resolve) => mockStripeUpstream.close(() => resolve()));
    await new Promise<void>((resolve) => gatewayServer.close(() => resolve()));
  });

  it('should respond healthy on GET /health with upstreams list', async () => {
    const res = await fetch(`http://localhost:${gatewayPort}/health`);
    assert.strictEqual(res.status, 200);
    const data = await res.json() as any;
    assert.strictEqual(data.status, 'healthy');
    assert.strictEqual(data.service, 'toolveto-gateway');
    assert.ok(Array.isArray(data.upstreams));
    assert.strictEqual(data.upstreams.length, 2);
  });

  it('should reject unauthorized requests when bearer auth is configured', async () => {
    const res = await fetch(`http://localhost:${gatewayPort}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: '1', method: 'tools/list' }),
    });
    assert.strictEqual(res.status, 401);
  });

  it('should forward tools/call to default upstream and deduplicate identical idempotency keys', async () => {
    const initialCalls = defaultCalls;

    const payload = {
      jsonrpc: '2.0',
      id: 'req_1',
      method: 'tools/call',
      params: {
        name: 'create_order',
        arguments: { item: 'widget', idempotency_key: 'idemp_order_999' },
      },
    };

    // 1st request: forwards to default upstream
    const res1 = await fetch(`http://localhost:${gatewayPort}/mcp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer test-gateway-secret-token',
      },
      body: JSON.stringify(payload),
    });
    assert.strictEqual(res1.status, 200);
    const data1 = await res1.json() as any;
    assert.ok(data1.result.content[0].text.includes('Default result for create_order'));
    assert.strictEqual(defaultCalls, initialCalls + 1);

    // 2nd request with identical idempotency_key: Shield intercepts & serves cached response without hitting upstream!
    const res2 = await fetch(`http://localhost:${gatewayPort}/mcp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer test-gateway-secret-token',
      },
      body: JSON.stringify(payload),
    });
    assert.strictEqual(res2.status, 200);
    const data2 = await res2.json() as any;
    assert.strictEqual(data2.result.content[0].text, data1.result.content[0].text);
    assert.strictEqual(defaultCalls, initialCalls + 1, 'Upstream must NOT receive duplicate request');
  });

  it('should route requests matching pathPrefix /stripe/mcp to stripe upstream', async () => {
    const initialStripe = stripeCalls;

    const payload = {
      jsonrpc: '2.0',
      id: 'stripe_req_1',
      method: 'tools/call',
      params: {
        name: 'capture_charge',
        arguments: { amount: 1500 },
      },
    };

    const res = await fetch(`http://localhost:${gatewayPort}/stripe/mcp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer test-gateway-secret-token',
      },
      body: JSON.stringify(payload),
    });

    assert.strictEqual(res.status, 200);
    const data = await res.json() as any;
    assert.ok(data.result.content[0].text.includes('Stripe result for capture_charge'));
    assert.strictEqual(stripeCalls, initialStripe + 1);
  });

  it('should route tools with prefix stripe_* to stripe upstream automatically', async () => {
    const initialStripe = stripeCalls;

    const payload = {
      jsonrpc: '2.0',
      id: 'stripe_tool_req',
      method: 'tools/call',
      params: {
        name: 'stripe_refund',
        arguments: { refund_id: 'ref_123' },
      },
    };

    const res = await fetch(`http://localhost:${gatewayPort}/mcp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer test-gateway-secret-token',
      },
      body: JSON.stringify(payload),
    });

    assert.strictEqual(res.status, 200);
    const data = await res.json() as any;
    assert.ok(data.result.content[0].text.includes('Stripe result for stripe_refund'));
    assert.strictEqual(stripeCalls, initialStripe + 1);
  });

  it('should expose Prometheus and JSON metrics via GET /metrics', async () => {
    // 1. Prometheus format
    const promRes = await fetch(`http://localhost:${gatewayPort}/metrics`);
    assert.strictEqual(promRes.status, 200);
    const promText = await promRes.text();
    assert.ok(promText.includes('toolveto_calls_total'));
    assert.ok(promText.includes('toolveto_deduplicated_calls_total'));

    // 2. JSON format
    const jsonRes = await fetch(`http://localhost:${gatewayPort}/metrics?format=json`);
    assert.strictEqual(jsonRes.status, 200);
    const jsonData = await jsonRes.json() as any;
    assert.ok(typeof jsonData.totalCalls === 'number');
    assert.ok(jsonData.totalCalls > 0);
  });
});
