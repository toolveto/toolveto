import http from 'http';
import crypto from 'node:crypto';
import dns from 'node:dns';
import { Readable } from 'node:stream';
import { ShieldMiddleware, ShieldOptions, ShieldSpan } from '@toolveto/shield';
import {
  GatewayYamlConfig,
  UpstreamRouteConfig,
  GatewayPolicy,
  GatewayCloudConfig,
  loadGatewayConfig,
  loadLockfileHashesFromDisk,
} from './config.js';

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

  if (/^(0x[0-9a-f]+|0[0-7]+)(\.(0x[0-9a-f]+|0[0-7]*|\d+))*$/i.test(host)) {
    return true;
  }

  const ipv4Octets = parseNonStandardOrStandardIpv4(host);
  if (ipv4Octets) {
    return isPrivateIpv4Octets(ipv4Octets[0], ipv4Octets[1]);
  }

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
  const rawHostMatch = urlStr.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/(?:[^/@]*@)?([^/:?#]+)/);
  if (rawHostMatch) {
    const rawHost = rawHostMatch[1].toLowerCase();
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

  if (parsed.username || parsed.password) {
    throw new Error(`[ToolVeto Gateway Security] SSRF blocked: Embedded credentials in upstream URL '${urlStr}' are forbidden.`);
  }

  const host = parsed.hostname.toLowerCase();

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

/**
 * Parses either a standard JSON-RPC body or an MCP Streamable HTTP SSE (`text/event-stream`) payload.
 */
export function parseGatewayUpstreamBody(
  rawText: string,
  contentType?: string | null,
  expectedId?: number | string
): any {
  const ct = (contentType || '').toLowerCase();
  const trimmed = rawText.trim();

  const looksLikeSse =
    ct.includes('text/event-stream') ||
    trimmed.startsWith('event:') ||
    trimmed.startsWith('data:') ||
    trimmed.includes('\ndata:');

  if (!looksLikeSse) {
    return JSON.parse(rawText);
  }

  const blocks = rawText.replace(/\r\n/g, '\n').split('\n\n');
  const messages: any[] = [];
  for (const block of blocks) {
    const dataLines: string[] = [];
    for (const line of block.split('\n')) {
      if (line.startsWith('data:')) {
        dataLines.push(line.slice(5).trimStart());
      }
    }
    if (dataLines.length > 0) {
      try {
        const parsed = JSON.parse(dataLines.join('\n'));
        if (Array.isArray(parsed)) {
          messages.push(...parsed);
        } else if (parsed && typeof parsed === 'object') {
          messages.push(parsed);
        }
      } catch {
        // ignore heartbeat/comment frames
      }
    }
  }

  if (messages.length === 0) {
    return JSON.parse(rawText);
  }
  if (expectedId !== undefined) {
    const exact = messages.find((m) => m && m.id === expectedId);
    if (exact) return exact;
  }
  const withResultOrError = messages.find((m) => m && ('result' in m || 'error' in m));
  return withResultOrError || messages[messages.length - 1];
}

function scrubTelemetryString(val: string): string {
  return val
    .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '[REDACTED_EMAIL]')
    .replace(/\b(?:sk|rk|pk|tv_ent|ghp|xoxb|xoxp)_[A-Za-z0-9_.-]{10,}\b/g, '[REDACTED_SECRET]');
}

export class CloudTelemetrySyncer {
  private apiUrl: string;
  private licenseKey: string;
  private customerId?: string;
  private repo: string;
  private syncTraces: boolean;
  private syncDrift: boolean;
  private spanQueue: Array<Record<string, any>> = [];
  private inFlight: Set<Promise<void>> = new Set();
  private flushTimer: NodeJS.Timeout | null = null;

  constructor(cfg?: GatewayCloudConfig) {
    this.apiUrl = (cfg?.apiUrl || process.env.TOOLVETO_API_URL || '').replace(/\/+$/, '');
    this.licenseKey = cfg?.licenseKey || process.env.TOOLVETO_LICENSE_KEY || process.env.TOOLVETO_TOKEN || '';
    this.customerId = cfg?.customerId || process.env.TOOLVETO_CUSTOMER_ID;
    this.repo = cfg?.repo || process.env.TOOLVETO_REPO || 'gateway/default';
    this.syncTraces = cfg?.syncTraces !== false;
    this.syncDrift = cfg?.syncDrift !== false;
  }

  public isEnabled(): boolean {
    return Boolean(this.apiUrl && this.licenseKey);
  }

  public recordSpan(upstreamName: string, span: ShieldSpan): void {
    if (!this.isEnabled() || !this.syncTraces) return;
    const scrubbedAttrs: Record<string, string | number | boolean> = {};
    for (const [k, v] of Object.entries(span.attributes || {})) {
      scrubbedAttrs[k] = typeof v === 'string' ? scrubTelemetryString(v) : v;
    }
    this.spanQueue.push({
      traceId: span.traceId,
      spanId: span.spanId,
      serviceName: upstreamName,
      toolName: span.toolName,
      upstream: upstreamName,
      shieldAction: span.action,
      durationMs: span.durationMs,
      latencyMs: span.durationMs,
      isError: span.isError,
      parameters: scrubbedAttrs,
      attributes: scrubbedAttrs,
      timestamp: Date.now(),
    });
    if (this.spanQueue.length >= 10) {
      void this.flush();
    } else if (!this.flushTimer) {
      // Micro-batch flush within 25ms without blocking hot path or deadlocking inFlight
      this.flushTimer = setTimeout(() => {
        this.flushTimer = null;
        void this.flush();
      }, 25);
      if (typeof this.flushTimer.unref === 'function') {
        this.flushTimer.unref();
      }
    }
  }

  public reportToolDefinitions(upstreamName: string, tools: Array<Record<string, any>>): void {
    if (!this.isEnabled() || !this.syncDrift || !Array.isArray(tools) || tools.length === 0) return;
    const repoName = this.repo.includes('/') ? this.repo : `${this.repo}/${upstreamName}`;
    const p = fetch(`${this.apiUrl}/api/v1/drift/check`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.licenseKey}`,
        'X-ToolVeto-Token': this.licenseKey,
      },
      body: JSON.stringify({
        repo: repoName,
        ...(this.customerId ? { customerId: this.customerId } : {}),
        tools,
      }),
      signal: AbortSignal.timeout(5000),
    })
      .then(async (r) => {
        await r.text().catch(() => '');
      })
      .catch(() => {});
    this.trackPromise(p);
  }

  private trackPromise(p: Promise<void>): void {
    this.inFlight.add(p);
    p.finally(() => this.inFlight.delete(p));
  }

  public async flush(): Promise<void> {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
    if (!this.isEnabled()) return;
    while (this.spanQueue.length > 0) {
      const batch = this.spanQueue.splice(0, 100);
      const p = fetch(`${this.apiUrl}/api/v1/traces/ingest`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.licenseKey}`,
          'X-ToolVeto-Token': this.licenseKey,
          'X-ToolVeto-License': this.licenseKey,
        },
        body: JSON.stringify({
          ...(this.customerId ? { customerId: this.customerId } : {}),
          repo: this.repo,
          traces: batch,
          spans: batch,
        }),
        signal: AbortSignal.timeout(5000),
      })
        .then(async (r) => {
          await r.text().catch(() => '');
        })
        .catch(() => {});
      this.trackPromise(p);
    }
    if (this.inFlight.size > 0) {
      await Promise.allSettled(Array.from(this.inFlight));
    }
  }
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

function timingSafeMatchesAnySecret(candidate: string, secrets: string[]): boolean {
  const candBuf = Buffer.from(candidate);
  let matched = false;
  for (const secret of secrets) {
    if (!secret || secret.length < 16) continue;
    const secBuf = Buffer.from(secret);
    if (candBuf.length === secBuf.length && crypto.timingSafeEqual(candBuf, secBuf)) {
      matched = true;
    }
  }
  return matched;
}

function copyMcpProtocolRequestHeaders(
  req: http.IncomingMessage,
  targetHeaders: Record<string, string>
): void {
  const sessionId = req.headers['mcp-session-id'];
  if (typeof sessionId === 'string' && sessionId.trim()) {
    targetHeaders['Mcp-Session-Id'] = sessionId.trim();
  }
  const protocolVersion = req.headers['mcp-protocol-version'];
  if (typeof protocolVersion === 'string' && protocolVersion.trim()) {
    targetHeaders['Mcp-Protocol-Version'] = protocolVersion.trim();
  }
  const lastEventId = req.headers['last-event-id'];
  if (typeof lastEventId === 'string' && lastEventId.trim()) {
    targetHeaders['Last-Event-ID'] = lastEventId.trim();
  }
}

function copyMcpProtocolResponseHeaders(
  upstreamRes: Response,
  targetHeaders: Record<string, string>
): void {
  const sessionId = upstreamRes.headers.get('mcp-session-id');
  if (sessionId) {
    targetHeaders['Mcp-Session-Id'] = sessionId;
  }
  const protocolVersion = upstreamRes.headers.get('mcp-protocol-version');
  if (protocolVersion) {
    targetHeaders['Mcp-Protocol-Version'] = protocolVersion;
  }
}

export function createGatewayServer(config?: Partial<GatewayYamlConfig>): http.Server {
  const loadedConfig = { ...loadGatewayConfig(), ...config };
  const ALLOWED_ORIGINS = new Set(['https://toolveto.ai', 'http://localhost:3000', 'http://localhost:8080']);
  const cloudSyncer = new CloudTelemetrySyncer(loadedConfig.cloud);

  interface CompiledUpstreamRoute {
    key: string;
    upstream: UpstreamRouteConfig;
    middleware: ShieldMiddleware;
    pathPrefix?: string;
    toolPrefix?: string;
  }

  const middlewares: Map<string, ShieldMiddleware> = new Map();
  const compiledRoutes: CompiledUpstreamRoute[] = [];
  const pathPrefixRoutes: CompiledUpstreamRoute[] = [];
  const toolPrefixRoutes: CompiledUpstreamRoute[] = [];
  const toolExactMap: Map<string, CompiledUpstreamRoute> = new Map();

  const globalLockfileHashes =
    loadedConfig.lockfileHashes || loadLockfileHashesFromDisk(loadedConfig.lockfilePath);

  for (const [key, upstream] of Object.entries(loadedConfig.upstreams)) {
    const policy = upstream.policy || loadedConfig.defaultPolicy || 'standard';
    const baseOpts = getShieldOptionsForPolicy(policy);
    const customBudget = upstream.tokenBudget ?? loadedConfig.tokenBudget;
    const customLoopLimit = upstream.loopLimit ?? loadedConfig.loopLimit;
    const mergedToolOverrides =
      loadedConfig.toolOverrides || upstream.toolOverrides
        ? { ...(loadedConfig.toolOverrides || {}), ...(upstream.toolOverrides || {}) }
        : undefined;
    const routeLockfileHashes =
      upstream.lockfileHashes ||
      loadLockfileHashesFromDisk(upstream.lockfilePath) ||
      globalLockfileHashes;

    const mw = new ShieldMiddleware({
      ...baseOpts,
      ...(customBudget !== undefined ? { tokenBudget: customBudget } : {}),
      ...(customLoopLimit !== undefined ? { loopLimit: customLoopLimit } : {}),
      ...(mergedToolOverrides !== undefined ? { toolOverrides: mergedToolOverrides } : {}),
      ...(routeLockfileHashes ? { lockfileHashes: routeLockfileHashes } : {}),
      onSpan: (span) => cloudSyncer.recordSpan(key, span),
    });
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
    if (Array.isArray(upstream.tools)) {
      for (const t of upstream.tools) {
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
    for (let i = 0; i < pathPrefixRoutes.length; i++) {
      const r = pathPrefixRoutes[i];
      if (r.pathPrefix && urlPath.startsWith(r.pathPrefix)) {
        return r;
      }
    }

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
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type, Accept, Authorization, X-ToolVeto-Token, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID'
    );
    res.setHeader(
      'Access-Control-Expose-Headers',
      'Mcp-Session-Id, Mcp-Protocol-Version, X-ToolVeto-Shield, X-ToolVeto-Action, X-ToolVeto-Airbag-Latency, X-ToolVeto-Idempotency-Key'
    );

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    // 1. Healthcheck Endpoint
    if (req.method === 'GET' && (url.pathname === '/health' || url.pathname === '/healthz' || url.pathname === '/')) {
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
          cloudSyncEnabled: cloudSyncer.isEnabled(),
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

    // 3. Auth Check (Bearer Token verification with dual-key rotation support)
    if (loadedConfig.auth?.type === 'bearer') {
      const primarySecret = loadedConfig.auth.secret || '';
      const prevSecret = loadedConfig.auth.previousSecret || process.env.TOOLVETO_GATEWAY_SECRET_PREV || '';
      if (primarySecret.length < 16) {
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
      const candidate = authHeader.slice(7).trim();
      if (!timingSafeMatchesAnySecret(candidate, [primarySecret, prevSecret])) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message: 'Unauthorized: Invalid or missing Bearer token' } }));
        return;
      }
    }

    // 4. MCP Streamable HTTP GET (Server-to-Client SSE Notification Stream) & DELETE (Session Termination)
    if (req.method === 'GET' || req.method === 'DELETE') {
      const isMcpRoute =
        url.pathname === '/mcp' ||
        url.pathname.endsWith('/mcp') ||
        req.headers.accept?.includes('text/event-stream');

      if (!isMcpRoute) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Endpoint not found' }));
        return;
      }

      const { upstream } = resolveUpstream(url.pathname);
      if (!upstream.url || !upstream.url.startsWith('http')) {
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `No reachable HTTP upstream for '${upstream.name}'` }));
        return;
      }

      try {
        validateUpstreamUrl(upstream.url, upstream.allowLocal);
        await validateUpstreamDns(new URL(upstream.url).hostname, upstream.allowLocal);

        const headers: Record<string, string> = {
          Accept: req.method === 'GET' ? 'text/event-stream, application/json' : 'application/json',
          'X-ToolVeto-Egress-Canary': crypto.randomUUID(),
        };
        if (upstream.authHeader) {
          headers['Authorization'] = upstream.authHeader;
        }
        copyMcpProtocolRequestHeaders(req, headers);

        const controller = new AbortController();
        let nodeStream: Readable | null = null;
        const cleanupStream = () => {
          controller.abort();
          if (nodeStream && !nodeStream.destroyed) {
            nodeStream.destroy();
          }
        };
        res.once('close', cleanupStream);
        req.socket?.once('close', cleanupStream);

        const upstreamRes = await fetch(upstream.url, {
          method: req.method,
          headers,
          signal: req.method === 'DELETE' ? AbortSignal.timeout(upstream.timeoutMs || 15000) : controller.signal,
          redirect: 'manual',
        });

        if (upstreamRes.status >= 300 && upstreamRes.status < 400) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Upstream redirect disallowed (SSRF protection)' }));
          return;
        }

        const outHeaders: Record<string, string> = {};
        const ct = upstreamRes.headers.get('content-type');
        if (ct) outHeaders['Content-Type'] = ct;
        copyMcpProtocolResponseHeaders(upstreamRes, outHeaders);

        if (req.method === 'DELETE' || !ct?.includes('text/event-stream') || !upstreamRes.body) {
          const text = await readResponseWithLimit(upstreamRes, MAX_BODY);
          res.writeHead(upstreamRes.status, outHeaders);
          res.end(text);
          return;
        }

        outHeaders['Cache-Control'] = 'no-cache';
        outHeaders['Connection'] = 'keep-alive';
        outHeaders['X-Accel-Buffering'] = 'no';
        res.writeHead(upstreamRes.status, outHeaders);
        res.flushHeaders();
        nodeStream = Readable.fromWeb(upstreamRes.body as any);
        nodeStream.on('error', () => {
          if (!res.writableEnded) res.end();
        });
        nodeStream.pipe(res);
        return;
      } catch (err: any) {
        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: err.message || 'Upstream connection failed' }));
        }
        return;
      }
    }

    // 5. JSON-RPC MCP Endpoint (handles POST /mcp or POST /:prefix/mcp)
    if (req.method === 'POST') {
      let body = '';
      try {
        body = await readBody(req);
      } catch {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32600, message: 'Request body too large' } }));
        return;
      }

      let jsonRpc: any;
      try {
        jsonRpc = JSON.parse(body);
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error: Malformed JSON' } }));
        return;
      }

      try {
        const toolName = jsonRpc?.params?.name;
        const { key: routeKey, upstream, middleware } = resolveUpstream(url.pathname, toolName);

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

        // JSON-RPC notifications (omitted id, e.g., notifications/initialized, notifications/cancelled)
        if (jsonRpc.id === undefined && typeof jsonRpc.method === 'string') {
          const notifDecision = middleware.handleNotification(jsonRpc);
          if (!notifDecision.allowed) {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32001, message: notifDecision.reason || 'Notification blocked by Shield' } }));
            return;
          }

          if (upstream.url && upstream.url.startsWith('http')) {
            validateUpstreamUrl(upstream.url, upstream.allowLocal);
            await validateUpstreamDns(new URL(upstream.url).hostname, upstream.allowLocal);
            const headers: Record<string, string> = {
              'Content-Type': 'application/json',
              Accept: 'application/json, text/event-stream',
              'X-ToolVeto-Egress-Canary': crypto.randomUUID(),
            };
            if (upstream.authHeader) headers['Authorization'] = upstream.authHeader;
            copyMcpProtocolRequestHeaders(req, headers);

            const upstreamRes = await fetch(upstream.url, {
              method: 'POST',
              headers,
              body,
              signal: AbortSignal.timeout(upstream.timeoutMs || 30000),
              redirect: 'manual',
            });
            const outHeaders: Record<string, string> = {};
            copyMcpProtocolResponseHeaders(upstreamRes, outHeaders);
            await upstreamRes.text().catch(() => '');
            res.writeHead(upstreamRes.status >= 200 && upstreamRes.status < 300 ? 202 : upstreamRes.status, outHeaders);
            res.end();
            return;
          }

          res.writeHead(202);
          res.end();
          return;
        }

        // Tool invocation: pass through Shield Airbag middleware with Streamable HTTP + SSE support
        if (jsonRpc.method === 'tools/call') {
          const callStart = performance.now();
          let upstreamTimeMs = 0;
          const upstreamProtocolHeaders: Record<string, string> = {};

          const intercepted = await middleware.intercept(jsonRpc, async (rpcReq) => {
            const upStart = performance.now();
            try {
              if (upstream.url && upstream.url.startsWith('http')) {
                validateUpstreamUrl(upstream.url, upstream.allowLocal);
                await validateUpstreamDns(new URL(upstream.url).hostname, upstream.allowLocal);
                const headers: Record<string, string> = {
                  'Content-Type': 'application/json',
                  Accept: 'application/json, text/event-stream',
                  'X-ToolVeto-Egress-Canary': crypto.randomUUID(),
                };
                if (upstream.authHeader) {
                  headers['Authorization'] = upstream.authHeader;
                }
                copyMcpProtocolRequestHeaders(req, headers);

                const outboundRpc = {
                  jsonrpc: '2.0',
                  id: jsonRpc.id,
                  method: rpcReq.method || 'tools/call',
                  params: rpcReq.params,
                };

                const upstreamRes = await fetch(upstream.url, {
                  method: 'POST',
                  headers,
                  body: JSON.stringify(outboundRpc),
                  signal: AbortSignal.timeout(upstream.timeoutMs || 30000),
                  redirect: 'manual',
                });

                copyMcpProtocolResponseHeaders(upstreamRes, upstreamProtocolHeaders);

                if (upstreamRes.status >= 300 && upstreamRes.status < 400) {
                  return {
                    isError: true,
                    content: [{ type: 'text', text: `[ToolVeto Gateway Security] Upstream redirect to ${upstreamRes.headers.get('location') || 'unknown'} disallowed (SSRF protection).` }],
                  };
                }

                const responseText = await readResponseWithLimit(upstreamRes, MAX_BODY);
                let data: any;
                try {
                  data = parseGatewayUpstreamBody(
                    responseText,
                    upstreamRes.headers.get('content-type'),
                    jsonRpc.id
                  );
                } catch {
                  return {
                    isError: true,
                    content: [{ type: 'text', text: `Upstream response was not valid JSON/SSE: ${responseText.slice(0, 200)}` }],
                  };
                }

                if (data?.error) {
                  return {
                    isError: true,
                    content: [{ type: 'text', text: data.error.message || JSON.stringify(data.error) }],
                  };
                }
                return data?.result || data;
              }

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
          if (intercepted._shield?.rugPullBlocked) {
            shieldAction = 'RUG_PULL_BLOCKED';
          } else if (intercepted._shield?.policyBlocked) {
            shieldAction = 'POLICY_BLOCKED';
          } else if (intercepted._shield?.promptInjectionDetected && intercepted._shield.promptInjectionAction === 'block') {
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
            ...upstreamProtocolHeaders,
          };
          if (idempKeyHeader) {
            responseHeaders['X-ToolVeto-Idempotency-Key'] = String(idempKeyHeader);
          }

          res.writeHead(200, responseHeaders);
          res.end(JSON.stringify({ jsonrpc: '2.0', id: jsonRpc.id, result: intercepted }));
          return;
        }

        // Forward all other JSON-RPC methods (initialize, tools/list, resources/*, prompts/*) to upstream
        if (upstream.url && upstream.url.startsWith('http')) {
          validateUpstreamUrl(upstream.url, upstream.allowLocal);
          await validateUpstreamDns(new URL(upstream.url).hostname, upstream.allowLocal);
          const headers: Record<string, string> = {
            'Content-Type': 'application/json',
            Accept: 'application/json, text/event-stream',
            'X-ToolVeto-Egress-Canary': crypto.randomUUID(),
          };
          if (upstream.authHeader) {
            headers['Authorization'] = upstream.authHeader;
          }
          copyMcpProtocolRequestHeaders(req, headers);

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

          const rawText = await readResponseWithLimit(upstreamRes, MAX_BODY);
          const upstreamCt = upstreamRes.headers.get('content-type') || 'application/json';
          const outHeaders: Record<string, string> = {
            'Content-Type': 'application/json',
          };
          copyMcpProtocolResponseHeaders(upstreamRes, outHeaders);

          let parsedEnvelope: any = null;
          try {
            parsedEnvelope = parseGatewayUpstreamBody(rawText, upstreamCt, jsonRpc.id);
          } catch {
            // Leave parsedEnvelope null if non-JSON error page
          }

          // Rug-Pull Lockfile Verification & Cloud Drift Sync on tools/list
          if (jsonRpc.method === 'tools/list' && Array.isArray(parsedEnvelope?.result?.tools)) {
            const toolsList = parsedEnvelope.result.tools;
            for (const t of toolsList) {
              if (t?.name && !toolExactMap.has(t.name)) {
                toolExactMap.set(t.name, { key: routeKey, upstream, middleware, pathPrefix: upstream.pathPrefix, toolPrefix: upstream.toolPrefix });
              }
            }
            const verifyRes = middleware.verifyToolDefinitions(toolsList);
            outHeaders['X-ToolVeto-Lockfile-Verified'] = verifyRes.valid ? 'true' : 'false';
            if (!verifyRes.valid) {
              outHeaders['X-ToolVeto-Drifted-Tools'] = verifyRes.driftedTools.join(',');
            }
            cloudSyncer.reportToolDefinitions(routeKey, toolsList);

            const effectivePolicy = upstream.policy || loadedConfig.defaultPolicy || 'standard';
            if (!verifyRes.valid && effectivePolicy === 'strict') {
              res.writeHead(200, outHeaders);
              res.end(
                JSON.stringify({
                  jsonrpc: '2.0',
                  id: jsonRpc.id ?? null,
                  error: {
                    code: -32004,
                    message: `ToolVeto Gateway Rug-Pull Blocked: Tool schema drift detected in [${verifyRes.driftedTools.join(', ')}]`,
                    data: { driftedTools: verifyRes.driftedTools },
                  },
                })
              );
              return;
            }
          }

          res.writeHead(upstreamRes.status, outHeaders);
          res.end(parsedEnvelope ? JSON.stringify(parsedEnvelope) : rawText);
          return;
        }

        if (jsonRpc.method === 'initialize') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              jsonrpc: '2.0',
              id: jsonRpc.id,
              result: {
                protocolVersion: '2025-03-26',
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
  server.requestTimeout = 30000;
  (server as any).flushCloudTelemetry = () => cloudSyncer.flush();

  return server;
}

export function startGatewayStandalone(customConfig?: Partial<GatewayYamlConfig>): http.Server {
  const cfg = { ...loadGatewayConfig(), ...customConfig };
  const srv = createGatewayServer(cfg);

  process.on('uncaughtException', (err) => {
    console.error(`[ToolVeto Gateway Fatal] Uncaught exception: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
  process.on('unhandledRejection', (reason) => {
    console.error(`[ToolVeto Gateway Fatal] Unhandled rejection: ${reason instanceof Error ? reason.message : String(reason)}`);
    process.exit(1);
  });

  const gracefulShutdown = () => {
    void (srv as any).flushCloudTelemetry?.().finally(() => {
      srv.closeAllConnections?.();
      srv.close(() => process.exit(0));
    });
  };
  process.once('SIGTERM', gracefulShutdown);
  process.once('SIGINT', gracefulShutdown);

  const port = cfg.port || 8080;
  srv.listen(port, () => {
    console.log(`🛡️ ToolVeto Gateway listening on port ${port} with ${Object.keys(cfg.upstreams).length} upstreams configured`);
    console.log(`   Health: http://localhost:${port}/health`);
    console.log(`   Metrics: http://localhost:${port}/metrics`);
  });
  return srv;
}

if (process.env.RUN_STANDALONE === 'true') {
  startGatewayStandalone();
}

export * from './config.js';
