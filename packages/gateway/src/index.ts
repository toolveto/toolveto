import http from 'http';
import { ShieldMiddleware, ShieldOptions } from '@toolveto/shield';
import { GatewayYamlConfig, UpstreamRouteConfig, GatewayPolicy, loadGatewayConfig } from './config.js';

export function getShieldOptionsForPolicy(policy: GatewayPolicy = 'standard'): ShieldOptions {
  switch (policy) {
    case 'strict':
      return {
        idempotency: true,
        idempotencyTtlMs: 24 * 60 * 60 * 1000,
        loopLimit: { count: 3, windowMs: 60000 },
        promptInjectionScan: { action: 'block', scanOutput: true },
        tokenBudget: 2000,
      };
    case 'permissive':
      return {
        idempotency: true,
        idempotencyTtlMs: 60 * 60 * 1000,
        loopLimit: { count: 10, windowMs: 15000 },
        promptInjectionScan: { action: 'flag', scanOutput: false },
        tokenBudget: 8000,
      };
    case 'standard':
    default:
      return {
        idempotency: true,
        idempotencyTtlMs: 12 * 60 * 60 * 1000,
        loopLimit: { count: 5, windowMs: 30000 },
        promptInjectionScan: { action: 'sanitize', scanOutput: true },
        tokenBudget: 4000,
      };
  }
}

export function createGatewayServer(config?: Partial<GatewayYamlConfig>): http.Server {
  const loadedConfig = { ...loadGatewayConfig(), ...config };
  
  // Maintain a dedicated ShieldMiddleware per policy / upstream
  const middlewares: Map<string, ShieldMiddleware> = new Map();
  for (const [key, upstream] of Object.entries(loadedConfig.upstreams)) {
    const policy = upstream.policy || loadedConfig.defaultPolicy || 'standard';
    middlewares.set(key, new ShieldMiddleware(getShieldOptionsForPolicy(policy)));
  }

  function resolveUpstream(urlPath: string, toolName?: string): { upstream: UpstreamRouteConfig; middleware: ShieldMiddleware } {
    // 1. Match by URL path prefix (e.g. /stripe/mcp -> stripe)
    for (const [key, upstream] of Object.entries(loadedConfig.upstreams)) {
      if (upstream.pathPrefix && urlPath.startsWith(upstream.pathPrefix)) {
        return { upstream, middleware: middlewares.get(key)! };
      }
    }

    // 2. Match by tool name prefix (e.g. stripe_charge -> stripe)
    if (toolName) {
      for (const [key, upstream] of Object.entries(loadedConfig.upstreams)) {
        if (upstream.toolPrefix && toolName.startsWith(upstream.toolPrefix)) {
          return { upstream, middleware: middlewares.get(key)! };
        }
      }
    }

    // 3. Fallback to default or first upstream
    const defaultKey = loadedConfig.upstreams['default'] ? 'default' : Object.keys(loadedConfig.upstreams)[0];
    return {
      upstream: loadedConfig.upstreams[defaultKey],
      middleware: middlewares.get(defaultKey) || new ShieldMiddleware(getShieldOptionsForPolicy('standard')),
    };
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);

    // Universal CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-ToolVeto-Token');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    // 1. Healthcheck Endpoint
    if (req.method === 'GET' && (url.pathname === '/health' || url.pathname === '/')) {
      const allMetrics: Record<string, any> = {};
      for (const [k, m] of middlewares.entries()) {
        allMetrics[k] = m.getMetrics();
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          status: 'healthy',
          service: 'toolveto-gateway',
          version: loadedConfig.version || '1.0',
          upstreams: Object.keys(loadedConfig.upstreams).map((k) => ({
            name: k,
            url: loadedConfig.upstreams[k].url,
            prefix: loadedConfig.upstreams[k].pathPrefix || 'none',
            policy: loadedConfig.upstreams[k].policy || 'standard',
          })),
          metrics: allMetrics,
        })
      );
      return;
    }

    // 2. Metrics Endpoint (Prometheus + JSON)
    if (req.method === 'GET' && url.pathname === '/metrics') {
      const acceptsJson = req.headers.accept?.includes('application/json') || url.searchParams.get('format') === 'json';
      
      let totalCalls = 0;
      let totalDedupes = 0;
      let totalLoopsBroken = 0;
      let totalTruncated = 0;
      let totalInjectionsDetected = 0;
      let totalInjectionsBlocked = 0;

      for (const m of middlewares.values()) {
        const metrics = m.getMetrics();
        totalCalls += metrics.totalCalls;
        totalDedupes += metrics.deduplicatedCalls;
        totalLoopsBroken += metrics.loopsBroken;
        totalTruncated += metrics.payloadsTruncated;
        totalInjectionsDetected += metrics.promptInjectionsDetected;
        totalInjectionsBlocked += metrics.promptInjectionsBlocked;
      }

      if (acceptsJson) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            totalCalls,
            totalDedupes,
            totalLoopsBroken,
            totalTruncated,
            totalInjectionsDetected,
            totalInjectionsBlocked,
          })
        );
        return;
      }

      // Prometheus metrics format
      const promMetrics = [
        '# HELP toolveto_calls_total Total number of MCP tool calls processed by ToolVeto Gateway',
        '# TYPE toolveto_calls_total counter',
        `toolveto_calls_total ${totalCalls}`,
        '# HELP toolveto_deduplicated_calls_total Total number of idempotent calls served from cache',
        '# TYPE toolveto_deduplicated_calls_total counter',
        `toolveto_deduplicated_calls_total ${totalDedupes}`,
        '# HELP toolveto_loops_broken_total Total number of runaway retry loops halted by Shield',
        '# TYPE toolveto_loops_broken_total counter',
        `toolveto_loops_broken_total ${totalLoopsBroken}`,
        '# HELP toolveto_payloads_truncated_total Total number of context bombs truncated to token budget',
        '# TYPE toolveto_payloads_truncated_total counter',
        `toolveto_payloads_truncated_total ${totalTruncated}`,
        '# HELP toolveto_injections_detected_total Total number of prompt injection attempts detected',
        '# TYPE toolveto_injections_detected_total counter',
        `toolveto_injections_detected_total ${totalInjectionsDetected}`,
        '# HELP toolveto_injections_blocked_total Total number of prompt injection attempts blocked',
        '# TYPE toolveto_injections_blocked_total counter',
        `toolveto_injections_blocked_total ${totalInjectionsBlocked}`,
      ].join('\n');

      res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4; charset=utf-8' });
      res.end(promMetrics + '\n');
      return;
    }

    // 3. Auth Check (Bearer Token verification if configured)
    if (loadedConfig.auth?.type === 'bearer' && loadedConfig.auth.secret) {
      const authHeader = req.headers['authorization'];
      if (!authHeader || !authHeader.startsWith('Bearer ') || authHeader.slice(7).trim() !== loadedConfig.auth.secret) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message: 'Unauthorized: Invalid or missing Bearer token' } }));
        return;
      }
    }

    // 4. JSON-RPC MCP Endpoint (handles POST /mcp or POST /:prefix/mcp)
    if (req.method === 'POST') {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', async () => {
        try {
          const jsonRpc = JSON.parse(body);
          const toolName = jsonRpc.params?.name;
          const { upstream, middleware } = resolveUpstream(url.pathname, toolName);

          // If tool call, pass through Shield Airbag middleware with upstream policy
          if (jsonRpc.method === 'tools/call') {
            const intercepted = await middleware.intercept(jsonRpc, async (rpcReq) => {
              // Forward to actual upstream server via HTTP POST
              if (upstream.url && upstream.url.startsWith('http')) {
                const headers: Record<string, string> = { 'Content-Type': 'application/json' };
                if (upstream.authHeader) {
                  headers['Authorization'] = upstream.authHeader;
                } else if (req.headers['authorization']) {
                  headers['Authorization'] = req.headers['authorization'];
                }

                const upstreamRes = await fetch(upstream.url, {
                  method: 'POST',
                  headers,
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
                content: [{ type: 'text', text: `Upstream response from ${upstream.name} for ${rpcReq.params?.name}` }],
              };
            });

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ jsonrpc: '2.0', id: jsonRpc.id, result: intercepted }));
            return;
          }

          // Forward all other non-mutation methods (e.g. tools/list, initialize) directly to upstream
          if (upstream.url && upstream.url.startsWith('http')) {
            const headers: Record<string, string> = { 'Content-Type': 'application/json' };
            if (upstream.authHeader) {
              headers['Authorization'] = upstream.authHeader;
            } else if (req.headers['authorization']) {
              headers['Authorization'] = req.headers['authorization'];
            }

            const upstreamRes = await fetch(upstream.url, {
              method: 'POST',
              headers,
              body,
            });
            const data = await upstreamRes.text();
            res.writeHead(upstreamRes.status, { 'Content-Type': 'application/json' });
            res.end(data);
            return;
          }

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ jsonrpc: '2.0', id: jsonRpc.id, result: { status: 'forwarded', upstream: upstream.name } }));
        } catch (err: any) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32603, message: err.message } }));
        }
      });
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Endpoint not found' }));
  });

  return server;
}

const defaultLoaded = loadGatewayConfig();
const server = createGatewayServer(defaultLoaded);

if (process.env.RUN_STANDALONE === 'true') {
  const port = defaultLoaded.port || 8080;
  server.listen(port, () => {
    console.log(`🛡️ ToolVeto Gateway listening on port ${port} with ${Object.keys(defaultLoaded.upstreams).length} upstreams configured`);
    console.log(`   Health: http://localhost:${port}/health`);
    console.log(`   Metrics: http://localhost:${port}/metrics`);
  });
}

export { server };
export * from './config.js';

