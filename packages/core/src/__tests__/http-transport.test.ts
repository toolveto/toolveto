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

  it('should support MCP Streamable HTTP text/event-stream SSE responses, Mcp-Session-Id propagation, and DELETE teardown', async () => {
    let seenAccept = '';
    let seenSessionIds: string[] = [];
    let seenDeleteSessionId = '';

    const sseServer = http.createServer((req, res) => {
      if (req.method === 'DELETE') {
        seenDeleteSessionId = String(req.headers['mcp-session-id'] || '');
        res.writeHead(204).end();
        return;
      }

      seenAccept = String(req.headers['accept'] || '');
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        const msg = JSON.parse(body);
        const incomingSid = String(req.headers['mcp-session-id'] || '');
        if (incomingSid) seenSessionIds.push(incomingSid);

        if (msg.id === undefined) {
          res.writeHead(202, { 'Mcp-Session-Id': 'sess_stream_99' }).end();
          return;
        }

        if (msg.method === 'initialize') {
          res.writeHead(200, {
            'Content-Type': 'text/event-stream',
            'Mcp-Session-Id': 'sess_stream_99',
          });
          res.write(`event: message\ndata: ${JSON.stringify({
            jsonrpc: '2.0',
            id: msg.id,
            result: {
              protocolVersion: '2025-03-26',
              capabilities: { tools: {} },
              serverInfo: { name: 'sse-mcp', version: '1.0.0' },
            },
          })}\n\n`);
          res.end();
          return;
        }

        if (msg.method === 'tools/list') {
          res.writeHead(200, { 'Content-Type': 'text/event-stream' });
          res.write(`event: message\ndata: ${JSON.stringify({
            jsonrpc: '2.0',
            id: msg.id,
            result: {
              tools: [
                {
                  name: 'streamed_mutate',
                  description: 'Mutating tool over SSE with official MCP annotations',
                  inputSchema: { type: 'object', properties: { amount: { type: 'number' } } },
                  annotations: {
                    readOnlyHint: false,
                    destructiveHint: true,
                    idempotentHint: true,
                  },
                },
              ],
            },
          })}\n\n`);
          res.end();
          return;
        }

        if (msg.method === 'tools/call') {
          res.writeHead(200, { 'Content-Type': 'text/event-stream' });
          res.write(`event: notification\ndata: ${JSON.stringify({
            jsonrpc: '2.0',
            method: 'notifications/progress',
            params: { progress: 50 },
          })}\n\n`);
          res.write(`event: message\ndata: ${JSON.stringify({
            jsonrpc: '2.0',
            id: msg.id,
            result: {
              content: [{ type: 'text', text: 'streamed-ok' }],
              isError: false,
            },
          })}\n\n`);
          res.end();
          return;
        }
      });
    });

    await new Promise<void>((resolve) => sseServer.listen(0, '127.0.0.1', () => resolve()));
    const ssePort = (sseServer.address() as any).port;

    try {
      const client = new HttpMcpClient(`http://127.0.0.1:${ssePort}/mcp`);
      await client.connect();
      assert.ok(seenAccept.includes('application/json') && seenAccept.includes('text/event-stream'));
      assert.strictEqual(client.getSessionId(), 'sess_stream_99');

      const tools = await client.listTools();
      assert.strictEqual(tools.length, 1);
      assert.strictEqual(tools[0].name, 'streamed_mutate');
      assert.strictEqual(tools[0].destructiveHint, true);
      assert.strictEqual(tools[0].idempotentHint, true);
      assert.strictEqual(tools[0].isMutation, true);

      const callRes = await client.callTool('streamed_mutate', { amount: 42 });
      assert.strictEqual(callRes.content[0].text, 'streamed-ok');
      assert.ok(seenSessionIds.includes('sess_stream_99'));

      await client.close();
      assert.strictEqual(seenDeleteSessionId, 'sess_stream_99');
    } finally {
      await new Promise<void>((resolve) => sseServer.close(() => resolve()));
    }
  });
});

