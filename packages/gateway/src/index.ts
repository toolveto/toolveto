import http from 'http';
import crypto from 'node:crypto';
import { ShieldMiddleware, ShieldOptions } from '@toolveto/shield';
import { GatewayYamlConfig, UpstreamRouteConfig, GatewayPolicy, loadGatewayConfig } from './config.js';

const MAX_BODY = 1_048_576; // 1 MB limit

async function readBody(req: http.IncomingMessage, max = MAX_BODY): Promise<string> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const c of req) {
    const buf = Buffer.isBuffer(c) ? c : Buffer.from(c);
    size += buf.length;
    if (size > max) {
      req.destroy();
      throw new Error('body too large');
    }
    chunks.push(buf);
  }
  return Buffer.concat(chunks).toString('utf8');
}

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
    let url: URL;
    try {
      url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32600, message: 'Invalid URL or Host header' } }));
      return;
    }

    // CORS Allowlist
    const ALLOWED_ORIGINS = new Set(['https://toolveto.ai', 'http://localhost:3000', 'http://localhost:8080']);
    const origin = req.headers.origin as string;
    if (origin && ALLOWED_ORIGINS.has(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
    }
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
    if (loadedConfig.auth?.type === 'bearer') {
      if (!loadedConfig.auth.secret || loadedConfig.auth.secret.length < 16) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32603, message: 'Server configuration error: Gateway secret missing or <16 chars' } }));
        return;
      }
      const authHeader = req.headers['authorization'];
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message: 'Unauthorized: Invalid or missing Bearer token' } }));
        return;
      }
      const a = Buffer.from(authHeader.slice(7).trim());
      const b = Buffer.from(loadedConfig.auth.secret);
      if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message: 'Unauthorized: Invalid or missing Bearer token' } }));
        return;
      }
    }

    // 4. JSON-RPC MCP Endpoint (handles POST /mcp or POST /:prefix/mcp)
    if (req.method === 'POST') {
      let body = '';
      try {
        body = await readBody(req);
      } catch {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32600, message: 'Request body too large' } }));
        return;
      }

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
                // Zero-Trust: ONLY forward explicit upstream authentication credential.
                // NEVER forward incoming client's master gateway authorization token.
                if (upstream.authHeader) {
                  headers['Authorization'] = upstream.authHeader;
                }

                const upstreamRes = await fetch(upstream.url, {
                  method: 'POST',
                  headers,
                  body: JSON.stringify(rpcReq),
                  signal: AbortSignal.timeout(upstream.timeoutMs || 30000),
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
            // Zero-Trust: ONLY forward explicit upstream authentication credential.
            // NEVER forward incoming client's master gateway authorization token.
            if (upstream.authHeader) {
              headers['Authorization'] = upstream.authHeader;
            }

            const upstreamRes = await fetch(upstream.url, {
              method: 'POST',
              headers,
              body,
              signal: AbortSignal.timeout(upstream.timeoutMs || 30000),
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
        return;
      }

      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Endpoint not found' }));
    });

    server.keepAliveTimeout = 5000;
    server.headersTimeout = 6000;
    server.requestTimeout = 15000;

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

