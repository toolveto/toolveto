import { describe, it, before, after } from 'node:test';
import * as assert from 'node:assert';
import http from 'node:http';
import { HttpMcpClient } from '../transports/http.js';

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
          const json = JSON.parse(body);
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

          res.writeHead(404).end();
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
});
