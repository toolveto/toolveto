import http from 'http';
import crypto from 'node:crypto';
import dns from 'node:dns';
import { ShieldMiddleware, ShieldOptions } from '@toolveto/shield';
import { GatewayYamlConfig, UpstreamRouteConfig, GatewayPolicy, loadGatewayConfig } from './config.js';

const MAX_BODY = 1_048_576; // 1 MB limit

export const BLOCKED_PRIVATE_HOSTNAMES = new Set([
  'localhost',
  '127.0.0.1',
  '::1',
  '[::1]',
  '0.0.0.0',
  '::',
  '[::]',
  '169.254.169.254', // AWS/GCP/Azure instance metadata
  'metadata.google.internal',
  'instance-data',
]);

function isPrivateIpv4Octets(oct1: number, oct2: number): boolean {
  if (oct1 === 0 || oct1 === 10 || oct1 === 127) return true;
  if (oct1 === 169 && oct2 === 254) return true;
  if (oct1 === 192 && oct2 === 168) return true;
  if (oct1 === 172 && oct2 >= 16 && oct2 <= 31) return true;
  if (oct1 === 100 && oct2 >= 64 && oct2 <= 127) return true; // RFC 6598 CGNAT 100.64.0.0/10
  if (oct1 >= 224) return true; // Multicast & reserved
  return false;
}

function parseNonStandardOrStandardIpv4(rawHost: string): [number, number, number, number] | null {
  // Single integer IPv4 (decimal, hex, or octal), e.g., 2130706433, 0x7f000001
  if (/^(0x[0-9a-f]+|0[0-7]+|\d+)$/i.test(rawHost)) {
    let val: number;
    if (rawHost.toLowerCase().startsWith('0x')) {
      val = parseInt(rawHost, 16);
    } else if (rawHost.startsWith('0') && rawHost.length > 1) {
      val = parseInt(rawHost, 8);
    } else {
      val = parseInt(rawHost, 10);
    }
    if (!Number.isNaN(val) && val >= 0 && val <= 0xffffffff) {
      return [(val >>> 24) & 0xff, (val >>> 16) & 0xff, (val >>> 8) & 0xff, val & 0xff];
    }
  }

  // Dotted IPv4 (supports decimal, octal 0177.0.0.1, hex 0x7f.0.0.1, or 2/3-part shorthand)
  const parts = rawHost.split('.');
  if (parts.length >= 2 && parts.length <= 4 && parts.every((p) => /^(0x[0-9a-f]+|0[0-7]*|\d+)$/i.test(p))) {
    const nums = parts.map((p) => {
      if (p.toLowerCase().startsWith('0x')) return parseInt(p, 16);
      if (p.startsWith('0') && p.length > 1 && /^[0-7]+$/.test(p)) return parseInt(p, 8);
      return parseInt(p, 10);
    });
    if (nums.some((n) => Number.isNaN(n) || n < 0)) return null;
    if (parts.length === 4 && nums.every((n) => n <= 255)) {
      return [nums[0], nums[1], nums[2], nums[3]];
    }
    if (parts.length === 3 && nums[0] <= 255 && nums[1] <= 255 && nums[2] <= 0xffff) {
      return [nums[0], nums[1], (nums[2] >>> 8) & 0xff, nums[2] & 0xff];
    }
    if (parts.length === 2 && nums[0] <= 255 && nums[1] <= 0xffffff) {
      return [nums[0], (nums[1] >>> 16) & 0xff, (nums[1] >>> 8) & 0xff, nums[1] & 0xff];
    }
  }

  return null;
}

export function isPrivateIpOrBlockedHost(hostname: string): boolean {
  const raw = hostname.toLowerCase().trim();
  const host = raw.startsWith('[') && raw.endsWith(']') ? raw.slice(1, -1) : raw;

  if (BLOCKED_PRIVATE_HOSTNAMES.has(raw) || BLOCKED_PRIVATE_HOSTNAMES.has(host)) return true;
  if (host.endsWith('.localhost') || host.endsWith('.internal') || host.endsWith('.local')) return true;

  // Reject any non-standard octal/hex dotted IPv4 representation immediately, or check decoded IPv4 octets
  if (/^(0x[0-9a-f]+|0[0-7]+)(\.(0x[0-9a-f]+|0[0-7]*|\d+))*$/i.test(host)) {
    return true;
  }

  const ipv4Octets = parseNonStandardOrStandardIpv4(host);
  if (ipv4Octets) {
    return isPrivateIpv4Octets(ipv4Octets[0], ipv4Octets[1]);
  }

  // IPv6 loopback, unspecified, unique local (fc00::/7 -> fc.. / fd..), and link-local (fe80::/10 -> fe8.. / fe9.. / fea.. / feb..)
  if (
    host === '::1' ||
    host === '::' ||
    host === '0:0:0:0:0:0:0:1' ||
    host === '0:0:0:0:0:0:0:0' ||
    host.startsWith('fc') ||
    host.startsWith('fd') ||
    /^fe[89ab][0-9a-f]:/i.test(host) ||
    host.startsWith('fe80')
  ) {
    return true;
  }

  // IPv4-mapped IPv6 addresses: ::ffff:127.0.0.1 or ::ffff:7f00:1 (normalized by WhatWG URL)
  if (host.startsWith('::ffff:')) {
    const mappedPart = host.slice('::ffff:'.length);
    const mappedV4 = parseNonStandardOrStandardIpv4(mappedPart);
    if (mappedV4) {
      return isPrivateIpv4Octets(mappedV4[0], mappedV4[1]);
    }
    const hexMatch = mappedPart.match(/^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
    if (hexMatch) {
      const hi = parseInt(hexMatch[1], 16);
      const oct1 = (hi >>> 8) & 0xff;
      const oct2 = hi & 0xff;
      return isPrivateIpv4Octets(oct1, oct2);
    }
    return true;
  }

  return false;
}

export function validateUpstreamUrl(urlStr: string, allowLocal = false): void {
  // Check raw string for octal/hex/decimal IP tricks before URL normalization
  const rawHostMatch = urlStr.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/(?:[^/@]*@)?([^/:?#]+)/);
  if (rawHostMatch) {
    const rawHost = rawHostMatch[1].toLowerCase();
    // Reject octal (0177.0.0.1), hex (0x7f.0.0.1), or single-integer decimal (2130706433) IP encodings unconditionally
    if (
      /^(0x[0-9a-f]+|0[0-7]+|\d+)$/i.test(rawHost) ||
      rawHost.split('.').some((part) => /^0x[0-9a-f]+$/i.test(part) || (/^0[0-7]+$/.test(part) && part.length > 1))
    ) {
      throw new Error(`[ToolVeto Gateway Security] SSRF blocked: Non-standard decimal, octal, or hex IP encoding in '${urlStr}' is forbidden.`);
    }
  }

  const parsed = new URL(urlStr);
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`[ToolVeto Gateway Security] SSRF blocked: Unsupported protocol '${parsed.protocol}'.`);
  }

  // Block embedded credentials in upstream URL (e.g. http://user@evil.com)
  if (parsed.username || parsed.password) {
    throw new Error(`[ToolVeto Gateway Security] SSRF blocked: Embedded credentials in upstream URL '${urlStr}' are forbidden.`);
  }

  const host = parsed.hostname.toLowerCase();

  // Cloud metadata endpoint is strictly forbidden under all circumstances
  if (host === '169.254.169.254' || host === 'metadata.google.internal' || host === 'instance-data') {
    throw new Error(`[ToolVeto Gateway Security] SSRF blocked: Access to cloud instance metadata (${host}) is forbidden.`);
  }

  const isProduction = process.env.NODE_ENV === 'production';
  const isExplicitlyAllowed = allowLocal || process.env.TOOLVETO_ALLOW_LOCAL_UPSTREAMS === 'true';

  if (isProduction && !isExplicitlyAllowed) {
    if (isPrivateIpOrBlockedHost(host)) {
      throw new Error(`[ToolVeto Gateway Security] SSRF blocked: Upstream URL '${urlStr}' targets private subnet or internal host in production environment.`);
    }
  } else if (!isExplicitlyAllowed) {
    const isStandardLoopback = host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]';
    if (!isStandardLoopback && isPrivateIpOrBlockedHost(host)) {
      throw new Error(`[ToolVeto Gateway Security] SSRF blocked: Upstream URL '${urlStr}' targets private network address.`);
    }
  }
}

export async function validateUpstreamDns(hostname: string, allowLocal = false): Promise<void> {
  const isExplicitlyAllowed = allowLocal || process.env.TOOLVETO_ALLOW_LOCAL_UPSTREAMS === 'true';
  if (isExplicitlyAllowed) return;

  const cleanHost = hostname.toLowerCase().trim().replace(/^\[|\]$/g, '');
  const isProduction = process.env.NODE_ENV === 'production';
  const isStandardLoopback = cleanHost === 'localhost' || cleanHost === '127.0.0.1' || cleanHost === '::1';

  if (!isProduction && isStandardLoopback) {
    return;
  }

  if (isPrivateIpOrBlockedHost(cleanHost)) {
    throw new Error(`[ToolVeto Gateway Security] SSRF DNS check blocked: Host '${hostname}' is a private or reserved address.`);
  }

  // If it's already an IP literal, no DNS lookup needed beyond isPrivateIpOrBlockedHost
  if (/^\d+\.\d+\.\d+\.\d+$/.test(cleanHost) || cleanHost.includes(':')) {
    return;
  }

  const records = await dns.promises.lookup(cleanHost, { all: true });
  if (!records || records.length === 0) {
    throw new Error(`[ToolVeto Gateway Security] SSRF DNS check failed: Unable to resolve host '${hostname}'.`);
  }

  for (const record of records) {
    if (isPrivateIpOrBlockedHost(record.address)) {
      throw new Error(
        `[ToolVeto Gateway Security] SSRF DNS rebinding blocked: Host '${hostname}' resolved to private/internal IP '${record.address}'.`
      );
    }
  }
}

async function readResponseWithLimit(res: Response, maxBytes = MAX_BODY): Promise<string> {
  const cl = res.headers.get('content-length');
  if (cl && parseInt(cl, 10) > maxBytes) {
    throw new Error(`Upstream response exceeds ${maxBytes} byte limit`);
  }
  const text = await res.text();
  if (Buffer.byteLength(text, 'utf8') > maxBytes) {
    throw new Error(`Upstream response exceeds ${maxBytes} byte limit`);
  }
  return text;
}

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
  const ALLOWED_ORIGINS = new Set(['https://toolveto.ai', 'http://localhost:3000', 'http://localhost:8080']);

  interface CompiledUpstreamRoute {
    key: string;
    upstream: UpstreamRouteConfig;
    middleware: ShieldMiddleware;
    pathPrefix?: string;
    toolPrefix?: string;
  }

  // Precompile dedicated ShieldMiddleware and route tables once at gateway startup
  const middlewares: Map<string, ShieldMiddleware> = new Map();
  const compiledRoutes: CompiledUpstreamRoute[] = [];
  const pathPrefixRoutes: CompiledUpstreamRoute[] = [];
  const toolPrefixRoutes: CompiledUpstreamRoute[] = [];
  const toolExactMap: Map<string, CompiledUpstreamRoute> = new Map();

  for (const [key, upstream] of Object.entries(loadedConfig.upstreams)) {
    const policy = upstream.policy || loadedConfig.defaultPolicy || 'standard';
    const baseOpts = getShieldOptionsForPolicy(policy);
    const customBudget = upstream.tokenBudget ?? loadedConfig.tokenBudget;
    const mw = new ShieldMiddleware(
      customBudget !== undefined ? { ...baseOpts, tokenBudget: customBudget } : baseOpts
    );
    middlewares.set(key, mw);

    const route: CompiledUpstreamRoute = {
      key,
      upstream,
      middleware: mw,
      pathPrefix: upstream.pathPrefix,
      toolPrefix: upstream.toolPrefix,
    };
    compiledRoutes.push(route);
    if (upstream.pathPrefix) {
      pathPrefixRoutes.push(route);
    }
    if (upstream.toolPrefix) {
      toolPrefixRoutes.push(route);
    }
    if (Array.isArray((upstream as any).tools)) {
      for (const t of (upstream as any).tools) {
        const tName = typeof t === 'string' ? t : t?.name;
        if (tName) {
          toolExactMap.set(tName, route);
        }
      }
    }
  }

  const defaultRoute: CompiledUpstreamRoute =
    compiledRoutes.find((r) => r.key === 'default') ||
    compiledRoutes[0] || {
      key: 'default',
      upstream: { name: 'default', url: 'http://localhost:3000/mcp', policy: 'standard' },
      middleware: new ShieldMiddleware(getShieldOptionsForPolicy('standard')),
    };

  function resolveUpstream(urlPath: string, toolName?: string): CompiledUpstreamRoute {
    // 1. Match by URL path prefix (e.g. /stripe/mcp -> stripe)
    for (let i = 0; i < pathPrefixRoutes.length; i++) {
      const r = pathPrefixRoutes[i];
      if (r.pathPrefix && urlPath.startsWith(r.pathPrefix)) {
        return r;
      }
    }

    // 2. Match by O(1) indexed tool Map or tool name prefix (e.g. stripe_charge -> stripe)
    if (toolName) {
      const exactMatch = toolExactMap.get(toolName);
      if (exactMatch) {
        return exactMatch;
      }
      for (let i = 0; i < toolPrefixRoutes.length; i++) {
        const r = toolPrefixRoutes[i];
        if (r.toolPrefix && toolName.startsWith(r.toolPrefix)) {
          toolExactMap.set(toolName, r);
          return r;
        }
      }
    }

    // 3. Fallback to precompiled default route
    return defaultRoute;
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

    // CORS Allowlist & ToolVeto Shield Header
    res.setHeader('X-ToolVeto-Shield', 'active');
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

          // Handle MCP 2026-07-28 server/discover directly at gateway boundary
          if (jsonRpc.method === 'server/discover') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({
                jsonrpc: '2.0',
                id: jsonRpc.id,
                result: {
                  protocolVersion: '2026-07-28',
                  capabilities: {
                    tools: {},
                    tasks: { supported: true, inputRequired: true },
                  },
                  serverInfo: {
                    name: 'toolveto-gateway',
                    version: loadedConfig.version || '1.0',
                  },
                },
              })
            );
            return;
          }

          // If tool call, pass through Shield Airbag middleware with upstream policy
          if (jsonRpc.method === 'tools/call') {
            const callStart = performance.now();
            let upstreamTimeMs = 0;
            const intercepted = await middleware.intercept(jsonRpc, async (rpcReq) => {
              const upStart = performance.now();
              try {
                // Forward to actual upstream server via HTTP POST
                if (upstream.url && upstream.url.startsWith('http')) {
                  validateUpstreamUrl(upstream.url, upstream.allowLocal);
                  await validateUpstreamDns(new URL(upstream.url).hostname, upstream.allowLocal);
                  const headers: Record<string, string> = {
                    'Content-Type': 'application/json',
                    'X-ToolVeto-Egress-Canary': crypto.randomUUID(),
                  };
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
                    redirect: 'manual',
                  });

                  if (upstreamRes.status >= 300 && upstreamRes.status < 400) {
                    return {
                      isError: true,
                      content: [{ type: 'text', text: `[ToolVeto Gateway Security] Upstream redirect to ${upstreamRes.headers.get('location') || 'unknown'} disallowed (SSRF protection).` }],
                    };
                  }

                  const responseText = await readResponseWithLimit(upstreamRes, MAX_BODY);
                  let data: any;
                  try {
                    data = JSON.parse(responseText);
                  } catch {
                    return {
                      isError: true,
                      content: [{ type: 'text', text: `Upstream response was not valid JSON: ${responseText.slice(0, 200)}` }],
                    };
                  }

                  if (data.error) {
                    return {
                      isError: true,
                      content: [{ type: 'text', text: data.error.message || JSON.stringify(data.error) }],
                    };
                  }
                  return data.result || data;
                }

                // Non-reachable or non-HTTP upstream: fail closed and never fabricate
                return {
                  isError: true,
                  content: [{ type: 'text', text: `[ToolVeto Gateway] No reachable HTTP upstream for '${upstream.name}'. Refusing to fabricate a response.` }],
                };
              } finally {
                upstreamTimeMs = performance.now() - upStart;
              }
            });

            const airbagLatencyMs = Math.max(0.01, Number((performance.now() - callStart - upstreamTimeMs).toFixed(2)));
            let shieldAction = 'PASS';
            if (intercepted._shield?.promptInjectionDetected && intercepted._shield.promptInjectionAction === 'block') {
              shieldAction = 'INJECTION_BLOCKED';
            } else if (intercepted._shield?.promptInjectionDetected && intercepted._shield.promptInjectionAction === 'sanitize') {
              shieldAction = 'INJECTION_SANITIZED';
            } else if (intercepted._shield?.loopChecked) {
              shieldAction = 'LOOP_BROKEN';
            } else if (intercepted._shield?.cached) {
              shieldAction = 'DEDUPLICATED';
            } else if (intercepted._shield?.truncated) {
              shieldAction = 'BUDGET_TRUNCATED';
            }

            const idempKeyHeader =
              intercepted._shield?.idempotencyKey ||
              jsonRpc.params?.arguments?.idempotency_key ||
              jsonRpc.params?.arguments?.idempotencyKey;

            const responseHeaders: Record<string, string> = {
              'Content-Type': 'application/json',
              'X-ToolVeto-Shield': 'active',
              'X-ToolVeto-Action': shieldAction,
              'X-ToolVeto-Airbag-Latency': `${airbagLatencyMs}ms`,
            };
            if (idempKeyHeader) {
              responseHeaders['X-ToolVeto-Idempotency-Key'] = String(idempKeyHeader);
            }

            res.writeHead(200, responseHeaders);
            res.end(JSON.stringify({ jsonrpc: '2.0', id: jsonRpc.id, result: intercepted }));
            return;
          }

          // Forward all other non-mutation methods (e.g. tools/list, initialize) directly to upstream
          if (upstream.url && upstream.url.startsWith('http')) {
            validateUpstreamUrl(upstream.url, upstream.allowLocal);
            await validateUpstreamDns(new URL(upstream.url).hostname, upstream.allowLocal);
            const headers: Record<string, string> = {
              'Content-Type': 'application/json',
              'X-ToolVeto-Egress-Canary': crypto.randomUUID(),
            };
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
              redirect: 'manual',
            });

            if (upstreamRes.status >= 300 && upstreamRes.status < 400) {
              res.writeHead(502, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32603, message: 'Upstream redirect disallowed (SSRF protection)' } }));
              return;
            }

            const data = await readResponseWithLimit(upstreamRes, MAX_BODY);
            res.writeHead(upstreamRes.status, { 'Content-Type': 'application/json' });
            res.end(data);
            return;
          }

          if (jsonRpc.method === 'server/discover' || jsonRpc.method === 'initialize') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({
                jsonrpc: '2.0',
                id: jsonRpc.id,
                result: {
                  protocolVersion: '2026-07-28',
                  capabilities: {
                    tools: {},
                    tasks: { supported: true, inputRequired: true },
                  },
                  serverInfo: {
                    name: 'toolveto-gateway',
                    version: loadedConfig.version || '1.0',
                  },
                },
              })
            );
            return;
          }

          if (jsonRpc.method?.startsWith('tasks/')) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({
                jsonrpc: '2.0',
                id: jsonRpc.id,
                result: {
                  id: jsonRpc.params?.id || 'task_default',
                  status: 'completed',
                  resultType: 'complete',
                },
              })
            );
            return;
          }

          if (upstream.url && /^https?:\/\//i.test(upstream.url)) {
            const upstreamRes = await fetch(upstream.url, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(jsonRpc),
            });
            const upstreamBody = await upstreamRes.text();
            res.writeHead(upstreamRes.status, { 'Content-Type': 'application/json' });
            res.end(upstreamBody);
            return;
          }

          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              jsonrpc: '2.0',
              id: jsonRpc.id ?? null,
              error: {
                code: -32603,
                message: `[ToolVeto Gateway] No reachable HTTP upstream for '${upstream.name}'. Refusing to fabricate a response.`,
              },
            })
          );
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

