import { describe, it, before, after } from 'node:test';
import * as assert from 'node:assert';
import http from 'node:http';
import { HttpMcpClient } from '../transports/http.js';
import { runEnvelopeFuzzCheck } from '../checks/envelope-fuzz.js';

describe('HttpMcpClient Streamable Transport', () => {
  let server: http.Server;
  let serverUrl: string;

  before(async () => {
    server = http.createServer((req, res) => {
      if (req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok' }));
        return;
      }

      if (req.method === 'POST') {
        let body = '';
        req.on('data', (chunk) => { body += chunk; });
        req.on('end', () => {
          let json: any;
          try {
            json = JSON.parse(body);
          } catch {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              jsonrpc: '2.0',
              id: null,
              error: { code: -32700, message: 'Parse error: Malformed JSON' },
            }));
            return;
          }

          if (!json || typeof json !== 'object' || Array.isArray(json) || json.jsonrpc !== '2.0') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              jsonrpc: '2.0',
              id: json?.id ?? null,
              error: { code: -32600, message: 'Invalid Request' },
            }));
            return;
          }

          // Notification (no id) -> 204 No Content
          if (json.id === undefined) {
            res.writeHead(204).end();
            return;
          }

          if (json.method === 'tools/list') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              jsonrpc: '2.0',
              id: json.id,
              result: {
                tools: [
                  {
                    name: 'test_http_tool',
                    description: 'A tool exposed over HTTP',
                    inputSchema: { type: 'object', properties: {} },
                  },
                ],
              },
            }));
            return;
          }

          if (json.method === 'tools/call') {
            if (json.params?.name === 'slow_timeout_tool') {
              setTimeout(() => {
                if (!res.writableEnded) {
                  res.writeHead(200, { 'Content-Type': 'application/json' });
                  res.end(JSON.stringify({ jsonrpc: '2.0', id: json.id, result: { content: [] } }));
                }
              }, 300);
              return;
            }

            if (json.params?.name === 'crash_500_tool') {
              res.writeHead(500, { 'Content-Type': 'text/plain' });
              res.end('Internal Server Panic: Segmentation fault');
              return;
            }

            if (json.params?.name === 'non_json_fuzz_tool') {
              res.writeHead(200, { 'Content-Type': 'text/html' });
              res.end('<html><body>Malformed gateway HTML response</body></html>');
              return;
            }

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              jsonrpc: '2.0',
              id: json.id,
              result: {
                content: [{ type: 'text', text: `Called ${json.params.name}` }],
                isError: false,
              },
            }));
            return;
          }

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            jsonrpc: '2.0',
            id: json.id,
            error: { code: -32601, message: `Method not found: ${json.method}` },
          }));
        });
      }
    });

    await new Promise<void>((resolve) => {
      server.listen(0, () => resolve());
    });
    const addr = server.address() as any;
    serverUrl = `http://127.0.0.1:${addr.port}`;
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('should list tools from remote HTTP MCP endpoint', async () => {
    const client = new HttpMcpClient(serverUrl);
    await client.connect();
    const tools = await client.listTools();
    assert.strictEqual(tools.length, 1);
    assert.strictEqual(tools[0].name, 'test_http_tool');
  });

  it('should execute tool call over HTTP MCP transport', async () => {
    const client = new HttpMcpClient(serverUrl);
    const resp = await client.callTool('test_http_tool', { foo: 'bar' });
    assert.strictEqual(resp.isError, false);
    assert.strictEqual(resp.content[0].text, 'Called test_http_tool');
  });

  it('should enforce real HTTP request timeout and surface panic error on hung endpoint', async () => {
    const client = new HttpMcpClient({ baseUrl: serverUrl, timeoutMs: 50 });
    await assert.rejects(
      async () => {
        await client.callTool('slow_timeout_tool', {});
      },
      (err: any) => {
        assert.strictEqual(err.isPanic, true, 'Timeout abort must mark error as panic');
        assert.ok(err.message.includes('dropped transport'));
        return true;
      }
    );
  });

  it('should handle HTTP 500 server crash and malformed non-JSON fuzz responses over live HTTP', async () => {
    const client = new HttpMcpClient({ baseUrl: serverUrl, timeoutMs: 2000 });

    // 1. HTTP 500 triggers panic error
    await assert.rejects(
      async () => {
        await client.callTool('crash_500_tool', {});
      },
      (err: any) => {
        assert.strictEqual(err.isPanic, true);
        assert.strictEqual(err.code, 500);
        return true;
      }
    );

    // 2. Wire-level envelope fuzzing against real local HTTP server
    const fuzzResult = await runEnvelopeFuzzCheck(
      { name: 'test_http_tool', inputSchema: { type: 'object', properties: {} } },
      client
    );
    assert.strictEqual(fuzzResult.status, 'PASS');
    assert.strictEqual(fuzzResult.evidence?.evidenceQuality, 'VERIFIED');

    // 3. sendRawRequest handles non-JSON body gracefully without crashing
    const rawNonJson = await client.sendRawRequest({
      jsonrpc: '2.0',
      id: 77,
      method: 'tools/call',
      params: { name: 'non_json_fuzz_tool', arguments: {} },
    });
    assert.strictEqual(rawNonJson.error.code, -32700);
  });
});

