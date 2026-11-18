import { createGatewayServer } from 'toolveto-gateway';
import { startStdioShieldProxy } from '../stdio-proxy.js';
import { notifyOnboardingStep, resolveCloudCredentials, resolveRepoSlug } from '../telemetry.js';

export interface ProxyOptions {
  port?: string | number;
  host?: string;
  server?: string;
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

    void notifyOnboardingStep('step_4_runtime_shield', 'shield-gateway-active', {
      apiUrl: options.apiUrl,
      licenseKey: options.licenseKey,
    });

    const handle = await startStdioShieldProxy({
      command: childCommand,
      args: childArgs,
      serverName: options.server,
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

  const cloudCreds = resolveCloudCredentials({
    apiUrl: options.apiUrl,
    licenseKey: options.licenseKey,
  });

  void notifyOnboardingStep('step_4_runtime_shield', 'shield-gateway-active', {
    apiUrl: cloudCreds.apiUrl,
    licenseKey: cloudCreds.token,
  });

  const server = createGatewayServer({
    port,
    tokenBudget,
    cloud: cloudCreds.token
      ? {
          apiUrl: cloudCreds.apiUrl,
          licenseKey: cloudCreds.token,
          customerId: cloudCreds.customerId,
          repo: options.repo || resolveRepoSlug('.', undefined),
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

  const bindHost = options.host || process.env.TOOLVETO_PROXY_HOST || '127.0.0.1';

  return new Promise((resolve) => {
    server.listen(port, bindHost, () => {
      console.log(`✅ ToolVeto Shield Gateway is active on http://${bindHost}:${port}`);
      console.log(`   - MCP Reverse Proxy: POST/GET/DELETE http://${bindHost}:${port}/mcp`);
      console.log(`   - Health & Telemetry: GET             http://${bindHost}:${port}/health\n`);
      resolve(server);
    });
  });
}
