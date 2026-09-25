import http from 'http';
import { ShieldMiddleware, ShieldOptions } from '@toolveto/shield';

export interface GatewayConfig {
  port: number;
  upstreamUrl: string;
  shieldOptions: ShieldOptions;
}

export function createGatewayServer(config: GatewayConfig): http.Server {
  const middleware = new ShieldMiddleware(config.shieldOptions);

  const server = http.createServer(async (req, res) => {
    // 1. Healthcheck Endpoint
    if (req.method === 'GET' && (req.url === '/health' || req.url === '/')) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          status: 'healthy',
          service: 'toolveto-gateway',
          upstreamUrl: config.upstreamUrl,
          metrics: middleware.getMetrics(),
        })
      );
      return;
    }

    // 2. JSON-RPC MCP Endpoint
    if (req.method === 'POST' && (req.url === '/mcp' || req.url === '/')) {
      let body = '';
      req.on('data', (chunk) => {
        body += chunk;
      });

      req.on('end', async () => {
        try {
          const jsonRpc = JSON.parse(body);

          // If tool call, pass through Shield Airbag middleware
          if (jsonRpc.method === 'tools/call') {
            const intercepted = await middleware.intercept(jsonRpc, async (rpcReq) => {
              // Forward to actual upstream server via HTTP POST
              if (config.upstreamUrl.startsWith('http')) {
                const upstreamRes = await fetch(config.upstreamUrl, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify(rpcReq),
                });
                const data = (await upstreamRes.json()) as any;
                if (data.error) {
                  return {
                    isError: true,
                    content: [{ type: 'text', text: data.error.message || JSON.stringify(data.error) }],
                  };
                }
                return data.result || data;
              }

              // In-process mock or fallback
              return {
                content: [{ type: 'text', text: `Upstream response for ${rpcReq.params?.name}` }],
              };
            });

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ jsonrpc: '2.0', id: jsonRpc.id, result: intercepted }));
            return;
          }

          // Forward all other non-mutation methods (e.g. tools/list, initialize) directly to upstream
          if (config.upstreamUrl.startsWith('http')) {
            const upstreamRes = await fetch(config.upstreamUrl, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body,
            });
            const data = await upstreamRes.text();
            res.writeHead(upstreamRes.status, { 'Content-Type': 'application/json' });
            res.end(data);
            return;
          }

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ jsonrpc: '2.0', id: jsonRpc.id, result: { status: 'forwarded' } }));
        } catch (err: any) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32603, message: err.message } }));
        }
      });
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
  });

  return server;
}

const defaultConfig: GatewayConfig = {
  port: Number(process.env.PORT) || 8080,
  upstreamUrl: process.env.UPSTREAM_URL || 'http://localhost:3000',
  shieldOptions: {
    idempotency: true,
    loopLimit: { count: 5, windowMs: 30000 },
    tokenBudget: 4000,
  },
};

const server = createGatewayServer(defaultConfig);

if (process.env.NODE_ENV !== 'test' && process.env.RUN_STANDALONE === 'true') {
  server.listen(defaultConfig.port, () => {
    console.log(`🛡️ ToolVeto Gateway listening on port ${defaultConfig.port} -> forwarding to ${defaultConfig.upstreamUrl}`);
  });
}

export { server };
