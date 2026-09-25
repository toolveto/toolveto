import { createGatewayServer } from 'toolveto-gateway';

export interface ProxyOptions {
  port?: string | number;
  upstream?: string;
  tokenBudget?: string | number;
}

export async function proxyCommand(options: ProxyOptions = {}): Promise<void> {
  const port = Number(options.port) || 8080;
  const upstreamUrl = options.upstream || 'http://localhost:3000/mcp';
  const tokenBudget = Number(options.tokenBudget) || 4000;

  console.log(`\n🛡️ Starting ToolVeto Shield Runtime Gateway`);
  console.log(`Port:        ${port}`);
  console.log(`Upstream:    ${upstreamUrl}`);
  console.log(`Protection:  Idempotency Deduplication, 5-count Loop Breaker, ${tokenBudget} Token Budget Cap\n`);

  const server = createGatewayServer({
    port,
    upstreams: {
      default: {
        name: 'default',
        url: upstreamUrl,
        policy: 'standard',
      },
    },
  });

  server.listen(port, () => {
    console.log(`✅ ToolVeto Shield Gateway is active on http://localhost:${port}`);
    console.log(`   - MCP Reverse Proxy: POST http://localhost:${port}/mcp`);
    console.log(`   - Health & Telemetry: GET  http://localhost:${port}/health\n`);
  });
}
