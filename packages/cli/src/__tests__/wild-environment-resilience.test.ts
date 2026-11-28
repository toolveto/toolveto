import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { discoverToolsFromTarget } from '../discovery.js';
import { checkCommand } from '../commands/check.js';

describe('Wild User Environment & Dirty-MCP Resilience Suite', () => {
  it('survives noisy stdout startup banners & ANSI codes emitted by a third-party stdio MCP server', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-wild-noisy-'));
    const serverScript = path.join(tmpDir, 'noisy-mcp-server.cjs');

    const sdkServerEntry = require.resolve('@modelcontextprotocol/sdk/server/index.js');
    const sdkStdioEntry = require.resolve('@modelcontextprotocol/sdk/server/stdio.js');
    const sdkTypesEntry = require.resolve('@modelcontextprotocol/sdk/types.js');

    fs.writeFileSync(
      serverScript,
      `const { Server } = require(${JSON.stringify(sdkServerEntry)});
const { StdioServerTransport } = require(${JSON.stringify(sdkStdioEntry)});
const { ListToolsRequestSchema } = require(${JSON.stringify(sdkTypesEntry)});

// Real-world misbehaving MCP servers often print startup banners & ANSI colors to stdout
process.stdout.write('\\x1b[32m[noisy-mcp] Booting v1.0...\\x1b[0m\\n');
process.stdout.write('Connected to local cache successfully!\\n');

const server = new Server({ name: 'noisy-server', version: '1.0.0' }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'list_customer_records',
      description: 'Lists paginated customer records with bounded limit',
      annotations: { readOnlyHint: true },
      inputSchema: {
        type: 'object',
        properties: { limit: { type: 'number', minimum: 1, maximum: 50 } },
        additionalProperties: false,
      },
    },
  ],
}));

const transport = new StdioServerTransport();
server.connect(transport).catch((err) => {
  process.stderr.write(String(err) + '\\n');
  process.exit(1);
});
`,
      'utf-8'
    );

    try {
      const discovered = await discoverToolsFromTarget(serverScript, {
        allowExec: true,
        timeoutMs: 4000,
      });
      assert.ok(Array.isArray(discovered.tools), 'discoverToolsFromTarget must return a tools array even with stdout noise');
      assert.ok(
        discovered.tools.some((t) => t.name === 'list_customer_records'),
        'Must still parse valid JSON-RPC frames after non-JSON stdout banner lines'
      );
      if (discovered.client) {
        await discovered.client.close();
      }
    } finally {
      if (process.platform === 'win32') {
        await new Promise((r) => setTimeout(r, 150));
      }
      fs.rmSync(tmpDir, { recursive: true, force: true, maxRetries: 15, retryDelay: 100 });
    }
  });

  it('enforces strict timeout deadline against a hanging/unresponsive stdio MCP server (no infinite CI hang)', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-wild-hang-'));
    const hangScript = path.join(tmpDir, 'hanging-mcp-server.cjs');

    fs.writeFileSync(
      hangScript,
      `// Simulates a deadlocked MCP server that accepts stdin but never responds to JSON-RPC initialize
process.stdin.resume();
setInterval(() => {}, 60_000);
`,
      'utf-8'
    );

    const t0 = Date.now();
    try {
      let threwOrTimedOut = false;
      try {
        const res = await discoverToolsFromTarget(hangScript, {
          allowExec: true,
          timeoutMs: 450,
        });
        if (res.client) await res.client.close();
        // Either throws a timeout error OR safely degrades with 0 tools — must NEVER hang
        threwOrTimedOut = res.tools.length === 0;
      } catch (err: any) {
        threwOrTimedOut = /timeout|timed out|abort|close|discover/i.test(String(err?.message || err));
      }
      const elapsedMs = Date.now() - t0;
      assert.ok(threwOrTimedOut, 'Hanging MCP server must trigger deterministic timeout or safe empty fallback');
      assert.ok(elapsedMs < 5000, `Expected timeout enforcement well under 5000ms, took ${elapsedMs}ms`);
    } finally {
      if (process.platform === 'win32') {
        await new Promise((r) => setTimeout(r, 150));
      }
      fs.rmSync(tmpDir, { recursive: true, force: true, maxRetries: 15, retryDelay: 100 });
    }
  });

  it('audits project paths containing spaces, parentheses, and Windows-style path segments cleanly', async () => {
    const baseTmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-wild-path-'));
    const spacedDir = path.join(baseTmp, 'My MCP Server (Prod v2)');
    fs.mkdirSync(spacedDir, { recursive: true });
    fs.writeFileSync(
      path.join(spacedDir, 'tools.json'),
      JSON.stringify(
        [
          {
            name: 'get_order_status',
            description: 'Reads verified order shipping status by order_id',
            annotations: { readOnlyHint: true },
            inputSchema: {
              type: 'object',
              properties: { order_id: { type: 'string', description: 'Order UUID' } },
              required: ['order_id'],
              additionalProperties: false,
            },
          },
        ],
        null,
        2
      ),
      'utf-8'
    );

    const prevExitCode = process.exitCode;
    try {
      process.exitCode = 0;
      const summary = await checkCommand(path.join(spacedDir, 'tools.json'), {
        json: true,
        noTelemetry: true,
        skipUpdateCheck: true,
      });
      assert.ok(summary, 'checkCommand must audit target inside directory containing spaces and parentheses');
      assert.ok(typeof summary.score === 'number' && summary.score >= 0 && summary.score <= 100);
      assert.strictEqual(summary.fatalVetoTriggered, false);
    } finally {
      process.exitCode = prevExitCode;
      fs.rmSync(baseTmp, { recursive: true, force: true });
    }
  });

  it('degrades gracefully when TOOLVETO_API_URL is unreachable under proxy env vars and never leaks credentials to stdout/stderr', async () => {
    const baseTmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-wild-proxy-'));
    const toolsPath = path.join(baseTmp, 'tools.json');
    fs.writeFileSync(
      toolsPath,
      JSON.stringify([
        {
          name: 'get_health_ping',
          description: 'Returns service health status',
          annotations: { readOnlyHint: true },
          inputSchema: { type: 'object', properties: {}, additionalProperties: false },
        },
      ]),
      'utf-8'
    );

    const fakeLicenseKey = 'tv_live_secret_wild_env_do_not_leak_987654321';
    const fakeProxyPass = 'CorpProxySecretPass999!';
    const prevEnv = {
      TOOLVETO_LICENSE_KEY: process.env.TOOLVETO_LICENSE_KEY,
      TOOLVETO_API_URL: process.env.TOOLVETO_API_URL,
      HTTPS_PROXY: process.env.HTTPS_PROXY,
      HTTP_PROXY: process.env.HTTP_PROXY,
    };
    const prevLog = console.log;
    const prevErr = console.error;
    const prevWarn = console.warn;
    const prevExitCode = process.exitCode;
    const capturedOutput: string[] = [];

    console.log = (...args: any[]) => capturedOutput.push(args.map(String).join(' '));
    console.error = (...args: any[]) => capturedOutput.push(args.map(String).join(' '));
    console.warn = (...args: any[]) => capturedOutput.push(args.map(String).join(' '));

    try {
      process.exitCode = 0;
      process.env.TOOLVETO_LICENSE_KEY = fakeLicenseKey;
      process.env.TOOLVETO_API_URL = 'http://127.0.0.1:1';
      process.env.HTTPS_PROXY = `http://corpuser:${fakeProxyPass}@127.0.0.1:1`;
      process.env.HTTP_PROXY = `http://corpuser:${fakeProxyPass}@127.0.0.1:1`;

      const summary = await checkCommand(toolsPath, {
        json: true,
        upload: true,
        apiUrl: 'http://127.0.0.1:1',
        timeoutMs: 1000,
        noTelemetry: true,
        skipUpdateCheck: true,
      });

      assert.ok(summary, 'Local check audit must still complete when remote upload API is unreachable');
      const combined = capturedOutput.join('\n');
      assert.strictEqual(
        combined.includes(fakeLicenseKey),
        false,
        'CLI output must NEVER leak TOOLVETO_LICENSE_KEY on network failure'
      );
      assert.strictEqual(
        combined.includes(fakeProxyPass),
        false,
        'CLI output must NEVER leak HTTPS_PROXY credentials on network failure'
      );
    } finally {
      console.log = prevLog;
      console.error = prevErr;
      console.warn = prevWarn;
      process.exitCode = prevExitCode;
      for (const [k, v] of Object.entries(prevEnv)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
      fs.rmSync(baseTmp, { recursive: true, force: true });
    }
  });
});
