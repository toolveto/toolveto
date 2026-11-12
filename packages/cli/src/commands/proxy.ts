import { createGatewayServer } from 'toolveto-gateway';
import { startStdioShieldProxy } from '../stdio-proxy.js';

export interface ProxyOptions {
  port?: string | number;
  upstream?: string;
  tokenBudget?: string | number;
  loopLimit?: string | number;
  strict?: boolean;
  stdio?: boolean;
  lockfile?: string;
  cmd?: string;
  apiUrl?: string;
  licenseKey?: string;
  repo?: string;
}

function isOperatorConfiguredLoopback(urlStr: string): boolean {
  try {
    const parsed = new URL(urlStr);
    const h = parsed.hostname.toLowerCase();
    return h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '[::1]';
  } catch {
    return false;
  }
}

export async function proxyCommand(
  options: ProxyOptions = {},
  passThroughArgs: string[] = []
): Promise<any> {
  const tokenBudget = Number(options.tokenBudget) || 4000;
  const loopLimit = Number(options.loopLimit) || 5;

  // Stdio proxy mode: either `--stdio` flag or `-- <command> [args...]`
  if (options.stdio || options.cmd || passThroughArgs.length > 0) {
    const childCommand = options.cmd || passThroughArgs[0];
    const childArgs = options.cmd ? passThroughArgs : passThroughArgs.slice(1);
    const upstreamUrl = !childCommand && options.upstream ? options.upstream : undefined;

    if (!childCommand && (!upstreamUrl || !/^https?:\/\//i.test(upstreamUrl))) {
      process.stderr.write(
        '[ToolVeto Shield] Error: --stdio requires either `-- <command> [args...]` or `--upstream <http-url>`.\n'
      );
      process.exitCode = 1;
      return;
    }

    const handle = await startStdioShieldProxy({
      command: childCommand,
      args: childArgs,
      upstreamUrl,
      tokenBudget,
      loopLimit,
      strict: Boolean(options.strict),
      lockfilePath: options.lockfile,
      apiUrl: options.apiUrl,
      licenseKey: options.licenseKey,
      repo: options.repo,
    });

    const exitCode = await handle.waitForExit();
    if (exitCode !== 0) {
      process.exitCode = exitCode;
    }
    return handle;
  }

  // HTTP / Streamable HTTP Gateway mode
  const port = options.port !== undefined ? Number(options.port) : 8080;
  const upstreamUrl = options.upstream || 'http://localhost:3000/mcp';

  if (!/^https?:\/\//i.test(upstreamUrl)) {
    console.error(
      '\n❌ --upstream must be an HTTP(S) URL in HTTP gateway mode, or pass `--stdio -- <command> [args...]` for stdio servers.\n'
    );
    process.exitCode = 1;
    return;
  }

  console.log(`\n🛡️ Starting ToolVeto Shield Runtime Gateway`);
  console.log(`Port:        ${port}`);
  console.log(`Upstream:    ${upstreamUrl}`);
  console.log(
    `Protection:  Idempotency Deduplication, ${loopLimit}-count Loop Breaker, ${tokenBudget} Token Budget Cap${options.strict ? ' (STRICT)' : ''}\n`
  );

  const server = createGatewayServer({
    port,
    tokenBudget,
    cloud:
      options.apiUrl || options.licenseKey
        ? {
            apiUrl: options.apiUrl,
            licenseKey: options.licenseKey,
            repo: options.repo,
          }
        : undefined,
    upstreams: {
      default: {
        name: 'default',
        url: upstreamUrl,
        policy: options.strict ? 'strict' : 'standard',
        tokenBudget,
        loopLimit: { count: loopLimit, windowMs: 30000 },
        lockfilePath: options.lockfile,
        allowLocal: isOperatorConfiguredLoopback(upstreamUrl),
      },
    },
  });

  return new Promise((resolve) => {
    server.listen(port, () => {
      console.log(`✅ ToolVeto Shield Gateway is active on http://localhost:${port}`);
      console.log(`   - MCP Reverse Proxy: POST/GET/DELETE http://localhost:${port}/mcp`);
      console.log(`   - Health & Telemetry: GET             http://localhost:${port}/health\n`);
      resolve(server);
    });
  });
}
