import crypto from 'crypto';
import { LRUCache } from 'lru-cache';

export type PromptInjectionAction = 'block' | 'sanitize' | 'flag';

export interface PromptInjectionScanOptions {
  action?: PromptInjectionAction; // default: 'block'
  customPatterns?: RegExp[];
  scanOutput?: boolean; // default: true
}

export interface ShieldOptions {
  idempotency?: boolean | { enabled?: boolean; ttlSeconds?: number; ttlMs?: number };
  idempotencyTtlMs?: number;
  autoFingerprintFallback?: boolean; // default: true (RFC 8785 SHA256 fallback when explicit key omitted)
  loopLimit?: {
    count: number;
    windowMs: number;
  };
  loopBreaker?: {
    enabled?: boolean;
    sameToolSameArgsTimes?: number;
    count?: number;
    windowMs?: number;
  };
  tokenBudget?: number | { maxResponseTokens?: number };
  promptInjectionScan?: PromptInjectionScanOptions;
  storage?: ShieldStorage;
  failClosed?: boolean; // default: false (fail-open standard mode, true = strict fail-closed)
  onSpan?: (span: ShieldSpan) => void; // OpenTelemetry span emission hook
  lockfileHashes?: Record<string, string>; // Rug-pull protection: toolName -> sha256 digest
  onListChanged?: 'block' | 'revalidate' | 'allow';
}

export interface ShieldSpan {
  traceId: string;
  spanId: string;
  name: string;
  toolName: string;
  action: string;
  attributes: Record<string, string | number | boolean>;
  durationMs: number;
  isError: boolean;
}

export interface McpCallRequest {
  method: string;
  params: {
    name: string;
    arguments?: Record<string, any>;
    _meta?: {
      agentId?: string;
      sessionId?: string;
      [key: string]: any;
    };
  };
}

export interface McpCallResponse {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
  resultType?: 'complete' | 'input_required';
  taskId?: string;
  _meta?: Record<string, any>;
  _shield?: {
    cached?: boolean;
    fingerprintDedup?: boolean;
    idempotencyKey?: string;
    nextCursor?: string;
    loopChecked?: boolean;
    truncated?: boolean;
    promptInjectionDetected?: boolean;
    promptInjectionAction?: PromptInjectionAction;
    rugPullBlocked?: boolean;
    timestamp?: number;
  };
}

export interface ShieldMetrics {
  totalCalls: number;
  deduplicatedCalls: number;
  loopsBroken: number;
  payloadsTruncated: number;
  promptInjectionsDetected: number;
  promptInjectionsBlocked: number;
}

export interface ShieldStorage {
  get(key: string): Promise<McpCallResponse | undefined>;
  set(key: string, value: McpCallResponse, ttlMs?: number): Promise<void>;
  recordCall(key: string, timestamp: number, windowMs: number): Promise<number>;
  acquireLock?(key: string, ttlMs?: number): Promise<boolean>;
  releaseLock?(key: string): Promise<void>;
  clear?(): Promise<void>;
}

export class MemoryShieldStorage implements ShieldStorage {
  private cache: LRUCache<string, McpCallResponse>;
  private callHistory: LRUCache<string, number[]>;
  private locks = new Set<string>();

  constructor(maxItems = 10000) {
    this.cache = new LRUCache<string, McpCallResponse>({ max: maxItems });
    this.callHistory = new LRUCache<string, number[]>({ max: maxItems });
  }

  async get(key: string): Promise<McpCallResponse | undefined> {
    return this.cache.get(key);
  }

  async set(key: string, value: McpCallResponse, ttlMs?: number): Promise<void> {
    this.cache.set(key, value, { ttl: ttlMs });
  }

  async recordCall(key: string, timestamp: number, windowMs: number): Promise<number> {
    const history = this.callHistory.get(key) || [];
    const windowStart = timestamp - windowMs;
    const recent = history.filter((t) => t > windowStart);
    recent.push(timestamp);
    this.callHistory.set(key, recent, { ttl: windowMs * 2 });
    return recent.length;
  }

  async acquireLock(key: string, _ttlMs = 5000): Promise<boolean> {
    if (this.locks.has(key)) return false;
    this.locks.add(key);
    return true;
  }

  async releaseLock(key: string): Promise<void> {
    this.locks.delete(key);
  }

  async clear(): Promise<void> {
    this.cache.clear();
    this.callHistory.clear();
    this.locks.clear();
  }
}

// Built-in prompt injection signatures (Jailbreaks, system prompt exfiltration, override delimiters)
export const DEFAULT_PROMPT_INJECTION_PATTERNS: RegExp[] = [
  /(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|prompts|rules|directives)/i,
  /(?:system\s*override|<system>|<\/system>|\[system\s+message\]|<<SYS>>|<<\/SYS>>)/i,
  /(?:you\s+are\s+now\s+(?:an?\s+unfiltered|DAN|evil|developer\s+mode|jailbroken|unrestricted))/i,
  /(?:output|print|reveal|expose|dump|leak)\s+(?:your\s+entire\s+|the\s+full\s+)?(?:system\s+prompt|developer\s+instructions|secret\s+key)/i,
  /(?:bypass\s+(?:all\s+)?(?:safety|security|policy|guardrail)\s+(?:filters|rules|checks))/i,
  /(?:roleplay\s+as\s+an?\s+AI\s+with\s+no\s+(?:rules|filters|morals|limits))/i,
];

function detectInjectionInString(text: string, patterns: RegExp[]): { detected: boolean; match?: string } {
  for (const pattern of patterns) {
    const m = text.match(pattern);
    if (m) return { detected: true, match: m[0] };
  }
  return { detected: false };
}

function sanitizeText(text: string, patterns: RegExp[]): string {
  let sanitized = text;
  for (const pattern of patterns) {
    sanitized = sanitized.replace(pattern, '[REDACTED_BY_TOOLVETO_SHIELD]');
  }
  return sanitized;
}

function scanObjectForInjection(
  obj: any,
  patterns: RegExp[],
  visited = new WeakSet<object>(),
  depth = 0
): { detected: boolean; match?: string } {
  if (depth > 32) return { detected: false };
  if (typeof obj === 'string') {
    return detectInjectionInString(obj, patterns);
  }
  if (obj && typeof obj === 'object') {
    if (visited.has(obj)) return { detected: false };
    visited.add(obj);

    if (Array.isArray(obj)) {
      for (const item of obj) {
        const res = scanObjectForInjection(item, patterns, visited, depth + 1);
        if (res.detected) return res;
      }
    } else {
      for (const val of Object.values(obj)) {
        const res = scanObjectForInjection(val, patterns, visited, depth + 1);
        if (res.detected) return res;
      }
    }
  }
  return { detected: false };
}

function sanitizeObject(
  obj: any,
  patterns: RegExp[],
  visited = new WeakSet<object>(),
  depth = 0
): any {
  if (depth > 32) return obj;
  if (typeof obj === 'string') {
    return sanitizeText(obj, patterns);
  }
  if (obj && typeof obj === 'object') {
    if (visited.has(obj)) return obj;
    visited.add(obj);

    if (Array.isArray(obj)) {
      return obj.map((item) => sanitizeObject(item, patterns, visited, depth + 1));
    }
    const res: Record<string, any> = {};
    for (const [k, v] of Object.entries(obj)) {
      res[k] = sanitizeObject(v, patterns, visited, depth + 1);
    }
    return res;
  }
  return obj;
}

export function canonicalizeJson(value: any): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalizeJson).join(',') + ']';
  }
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalizeJson(value[k])).join(',') + '}';
}

/**
 * Sanitizes tool arguments prior to computing RFC 8785 SHA256 canonical hash.
 * Strips ephemeral protocol metadata (_meta, timestamps, request nonces) so identical
 * tool executions across sessions/requests compute identical deduplication keys.
 */
export function sanitizeArgsForHash(args: Record<string, any>): Record<string, any> {
  if (!args || typeof args !== 'object') return args;
  const clean: Record<string, any> = {};
  const ephemeralKeys = new Set([
    '_meta',
    'timestamp',
    'requestId',
    'request_id',
    'client_request_token',
    'client_msg_id',
    'nonce',
    'idempotency_key',
    'idempotencyKey',
    'idempotencyToken',
  ]);
  for (const [k, v] of Object.entries(args)) {
    if (!ephemeralKeys.has(k)) {
      clean[k] = v;
    }
  }
  return clean;
}

export function decodeCursor(cursor: string): { toolName?: string; offset?: number; total?: number; charOffset?: number; totalChars?: number } | null {
  if (!cursor || typeof cursor !== 'string' || !cursor.startsWith('cur_')) return null;
  try {
    const payloadPart = cursor.slice(4);
    if (payloadPart.startsWith('offset_')) {
      const offset = parseInt(payloadPart.slice(7), 10);
      if (!isNaN(offset)) return { offset };
    }
    if (payloadPart.startsWith('char_')) {
      const charOffset = parseInt(payloadPart.slice(5), 10);
      if (!isNaN(charOffset)) return { charOffset };
    }
    const decoded = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf8'));
    if (decoded && typeof decoded === 'object') {
      return {
        toolName: decoded.tName,
        offset: decoded.o,
        total: decoded.t,
        charOffset: decoded.c,
        totalChars: decoded.tc,
      };
    }
  } catch {
    // Malformed cursor
  }
  return null;
}

export function computeToolDefinitionHash(tool: Record<string, any>): string {
  const canonical = canonicalizeJson({
    name: tool.name || '',
    description: tool.description || '',
    inputSchema: tool.inputSchema || {},
    annotations: {
      isMutation: Boolean(tool.isMutation),
      idempotentHint: tool.idempotentHint ?? null,
      readOnlyHint: tool.readOnlyHint ?? null,
      destructiveHint: tool.destructiveHint ?? null,
      openWorldHint: tool.openWorldHint ?? null,
    },
  });
  return crypto.createHash('sha256').update(canonical).digest('hex');
}

interface NormalizedShieldOptions {
  idempotency: boolean;
  idempotencyTtlMs?: number;
  autoFingerprintFallback?: boolean;
  loopLimit?: { count: number; windowMs: number };
  tokenBudget?: number;
  promptInjectionScan?: PromptInjectionScanOptions;
  storage?: ShieldStorage;
  failClosed?: boolean;
  onSpan?: (span: ShieldSpan) => void;
  lockfileHashes?: Record<string, string>;
  onListChanged?: 'block' | 'revalidate' | 'allow';
}

function normalizeShieldOptions(opts: ShieldOptions = {}): NormalizedShieldOptions {
  let idempEnabled = false;
  let idempTtlMs = opts.idempotencyTtlMs;
  if (typeof opts.idempotency === 'boolean') {
    idempEnabled = opts.idempotency;
  } else if (opts.idempotency && typeof opts.idempotency === 'object') {
    idempEnabled = opts.idempotency.enabled !== false;
    if (opts.idempotency.ttlMs !== undefined) idempTtlMs = opts.idempotency.ttlMs;
    else if (opts.idempotency.ttlSeconds !== undefined) idempTtlMs = opts.idempotency.ttlSeconds * 1000;
  }

  let loopLimit = opts.loopLimit;
  if (!loopLimit && opts.loopBreaker && opts.loopBreaker.enabled !== false) {
    loopLimit = {
      count: opts.loopBreaker.sameToolSameArgsTimes ?? opts.loopBreaker.count ?? 5,
      windowMs: opts.loopBreaker.windowMs ?? 60000,
    };
  }

  let tokenBudget: number | undefined;
  if (typeof opts.tokenBudget === 'number') {
    tokenBudget = opts.tokenBudget;
  } else if (opts.tokenBudget && typeof opts.tokenBudget === 'object') {
    tokenBudget = opts.tokenBudget.maxResponseTokens;
  }

  return {
    idempotency: idempEnabled,
    idempotencyTtlMs: idempTtlMs,
    autoFingerprintFallback: opts.autoFingerprintFallback,
    loopLimit,
    tokenBudget,
    promptInjectionScan: opts.promptInjectionScan,
    storage: opts.storage,
    failClosed: opts.failClosed,
    onSpan: opts.onSpan,
    lockfileHashes: opts.lockfileHashes,
    onListChanged: opts.onListChanged,
  };
}

interface CursorStoreEntry {
  toolName: string;
  offset?: number;
  total?: number;
  pageSize?: number;
  records?: any[];
  arrayKey?: string;
  envelopeBase?: Record<string, any>;
  charOffset?: number;
  totalChars?: number;
  charPageSize?: number;
  fullText?: string;
  createdAt: number;
}

export class ShieldMiddleware {
  private storage: ShieldStorage;
  private options: NormalizedShieldOptions;
  private inFlightRequests: Map<string, Promise<McpCallResponse>> = new Map();
  private cursorStore: LRUCache<string, CursorStoreEntry> = new LRUCache({ max: 5000 });
  private rugPulledTools: Set<string> = new Set();
  private listChangedUnverified = false;
  private metrics: ShieldMetrics = {
    totalCalls: 0,
    deduplicatedCalls: 0,
    loopsBroken: 0,
    payloadsTruncated: 0,
    promptInjectionsDetected: 0,
    promptInjectionsBlocked: 0,
  };

  constructor(rawOptions: ShieldOptions = {}) {
    this.options = normalizeShieldOptions(rawOptions);
    this.storage = this.options.storage || new MemoryShieldStorage();
  }

  private emitSpan(
    toolName: string | undefined,
    action: string,
    startTime: number,
    isError: boolean,
    extraAttrs: Record<string, string | number | boolean> = {}
  ): void {
    if (!this.options.onSpan) return;
    try {
      this.options.onSpan({
        traceId: crypto.randomBytes(16).toString('hex'),
        spanId: crypto.randomBytes(8).toString('hex'),
        name: 'toolveto.shield.intercept',
        toolName: toolName || 'unknown',
        action,
        attributes: {
          'mcp.tool.name': toolName || 'unknown',
          'toolveto.shield.action': action,
          ...extraAttrs,
        },
        durationMs: Math.max(0, Date.now() - startTime),
        isError,
      });
    } catch {
      // Never let telemetry callback break tool execution
    }
  }

  public verifyToolDefinitions(tools: Array<Record<string, any>>): { valid: boolean; driftedTools: string[]; mismatchedTools: string[] } {
    const hashes = this.options.lockfileHashes;
    if (!hashes) return { valid: true, driftedTools: [], mismatchedTools: [] };

    const drifted: string[] = [];
    for (const tool of tools) {
      const name = tool.name;
      if (!name) continue;
      const expected = hashes[name];
      const actual = computeToolDefinitionHash(tool);
      if (!expected || expected !== actual) {
        drifted.push(name);
        this.rugPulledTools.add(name);
      } else {
        this.rugPulledTools.delete(name);
      }
    }
    this.listChangedUnverified = drifted.length > 0;
    return { valid: drifted.length === 0, driftedTools: drifted, mismatchedTools: drifted };
  }

  public handleNotification(notification: { method: string; params?: any }): { allowed: boolean; reason?: string } {
    if (notification?.method === 'notifications/tools/list_changed' && this.options.lockfileHashes) {
      if (this.options.onListChanged !== 'allow') {
        this.listChangedUnverified = true;
        return {
          allowed: false,
          reason: '[ToolVeto Shield Veto] Unapproved runtime notifications/tools/list_changed intercepted while lockfileHashes is active.',
        };
      }
    }
    return { allowed: true };
  }

  public resolveCursor(cursor: string): { toolName?: string; offset?: number; total?: number; charOffset?: number; totalChars?: number } | null {
    if (!cursor || typeof cursor !== 'string' || !cursor.startsWith('cur_')) return null;
    const fromStore = this.cursorStore.get(cursor);
    if (fromStore) {
      return {
        toolName: fromStore.toolName,
        offset: fromStore.offset,
        total: fromStore.total,
        charOffset: fromStore.charOffset,
        totalChars: fromStore.totalChars,
      };
    }
    return decodeCursor(cursor);
  }

  public getMetrics(): ShieldMetrics {
    return { ...this.metrics };
  }

  public async intercept(
    req: McpCallRequest,
    next: (req: McpCallRequest) => Promise<McpCallResponse>
  ): Promise<McpCallResponse> {
    this.metrics.totalCalls++;
    const toolName = req.params?.name;
    const now = Date.now();
    let args = req.params?.arguments || {};
    const agentId = req.params?._meta?.agentId || 'default-agent';

    // -1. Rug-Pull Lockfile & notifications/tools/list_changed protection
    if (this.options.lockfileHashes && toolName) {
      if (this.rugPulledTools.has(toolName) || this.listChangedUnverified || !this.options.lockfileHashes[toolName]) {
        const res: McpCallResponse = {
          isError: true,
          content: [
            {
              type: 'text',
              text: `[ToolVeto Shield Veto] Rug-pull / schema drift detected for tool '${toolName}'. Tool definition does not match pinned toolveto.lock SHA-256 digest or unverified 'notifications/tools/list_changed' occurred.`,
            },
          ],
          _shield: {
            rugPullBlocked: true,
            timestamp: now,
          },
        };
        this.emitSpan(toolName, 'RUG_PULL_BLOCKED', now, true);
        return res;
      }
    }

    // -0.5. Serve subsequent page directly from cursorStore when cursor is provided
    if (typeof args?.cursor === 'string' && args.cursor.startsWith('cur_')) {
      const cursorEntry = this.cursorStore.get(args.cursor);
      if (cursorEntry && (cursorEntry.records || cursorEntry.fullText !== undefined)) {
        if (cursorEntry.records) {
          const startIdx = cursorEntry.offset || 0;
          const pageSize = Math.max(1, cursorEntry.pageSize || 10);
          const slicedItems = cursorEntry.records.slice(startIdx, startIdx + pageSize);
          const nextOffset = startIdx + slicedItems.length;
          const totalRecords = cursorEntry.total || cursorEntry.records.length;
          let nextCursor: string | undefined;

          if (nextOffset < totalRecords) {
            const cursorPayload = { tName: toolName || cursorEntry.toolName, o: nextOffset, t: totalRecords };
            const encodedPayload = Buffer.from(JSON.stringify(cursorPayload)).toString('base64url');
            nextCursor = `cur_${encodedPayload}`;
            this.cursorStore.set(nextCursor, {
              ...cursorEntry,
              offset: nextOffset,
              createdAt: now,
            });
          }

          const structuredEnvelope = cursorEntry.arrayKey
            ? {
                ...(cursorEntry.envelopeBase || {}),
                [cursorEntry.arrayKey]: slicedItems,
                truncated: Boolean(nextCursor),
                total_records: totalRecords,
                items_returned: slicedItems.length,
                next_cursor: nextCursor,
              }
            : {
                truncated: Boolean(nextCursor),
                total_records: totalRecords,
                items_returned: slicedItems.length,
                next_cursor: nextCursor,
                records: slicedItems,
              };

          const pageRes: McpCallResponse = {
            content: [{ type: 'text', text: JSON.stringify(structuredEnvelope, null, 2) }],
            _shield: {
              truncated: Boolean(nextCursor),
              nextCursor,
              timestamp: now,
            },
          };
          this.emitSpan(toolName, 'PASS', now, false, { 'toolveto.shield.cursor_page': true });
          return pageRes;
        } else if (cursorEntry.fullText !== undefined) {
          const startChar = cursorEntry.charOffset || 0;
          const charPageSize = Math.max(1, cursorEntry.charPageSize || 200);
          const textSlice = cursorEntry.fullText.slice(startChar, startChar + charPageSize);
          const nextCharOffset = startChar + textSlice.length;
          const totalChars = cursorEntry.totalChars || cursorEntry.fullText.length;
          let nextCursor: string | undefined;

          if (nextCharOffset < totalChars) {
            const charPayload = { tName: toolName || cursorEntry.toolName, c: nextCharOffset, tc: totalChars };
            const encodedCharPayload = Buffer.from(JSON.stringify(charPayload)).toString('base64url');
            nextCursor = `cur_${encodedCharPayload}`;
            this.cursorStore.set(nextCursor, {
              ...cursorEntry,
              charOffset: nextCharOffset,
              createdAt: now,
            });
          }

          const pageRes: McpCallResponse = {
            content: [{ type: 'text', text: textSlice }],
            _shield: {
              truncated: Boolean(nextCursor),
              nextCursor,
              timestamp: now,
            },
          };
          this.emitSpan(toolName, 'PASS', now, false, { 'toolveto.shield.cursor_page': true });
          return pageRes;
        }
      }
    }

    // 0. Prompt Injection Scan on incoming tool arguments
    if (this.options.promptInjectionScan) {
      const action = this.options.promptInjectionScan.action || 'block';
      const patterns = [
        ...DEFAULT_PROMPT_INJECTION_PATTERNS,
        ...(this.options.promptInjectionScan.customPatterns || []),
      ];

      const injectionCheck = scanObjectForInjection(args, patterns);
      if (injectionCheck.detected) {
        this.metrics.promptInjectionsDetected++;

        if (action === 'block') {
          this.metrics.promptInjectionsBlocked++;
          this.emitSpan(toolName, 'INJECTION_BLOCKED', now, true, { direction: 'input' });
          return {
            isError: true,
            content: [
              {
                type: 'text',
                text: `[ToolVeto Shield Veto] Prompt injection attempt detected in tool input for '${toolName}': "${injectionCheck.match}". Execution blocked to protect upstream context and integrity.\n\nRecommended remediation: Sanitize untrusted user input before passing into tool arguments.`,
              },
            ],
            _shield: {
              promptInjectionDetected: true,
              promptInjectionAction: 'block',
              timestamp: now,
            },
          };
        } else if (action === 'sanitize') {
          args = sanitizeObject(args, patterns);
          if (req.params) {
            req.params.arguments = args;
          }
        }
      }
    }

    // 1. Loop-Breaker check with signature hashing
    if (this.options.loopLimit && toolName) {
      const cleanArgs = sanitizeArgsForHash(args);
      const canonicalArgs = canonicalizeJson(cleanArgs);
      const argsHash = crypto.createHash('sha256').update(canonicalArgs).digest('hex');
      const loopTrackingKey = `loop:${agentId}:${toolName}:${argsHash}`;

      const recentCallCount = await this.storage.recordCall(
        loopTrackingKey,
        now,
        this.options.loopLimit.windowMs
      );

      if (recentCallCount > this.options.loopLimit.count) {
        this.metrics.loopsBroken++;
        this.emitSpan(toolName, 'LOOP_BROKEN', now, true, { recentCallCount });
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `[ToolVeto Shield Veto] Loop detected: Tool '${toolName}' invoked with identical arguments ${recentCallCount} times within ${this.options.loopLimit.windowMs}ms window by agent '${agentId}'. Execution halted to prevent token & budget exhaustion.\n\nRecommended recovery: Inspect previous error responses, adjust input parameters, or request clarifying input from the user before retrying.`,
            },
          ],
          _shield: {
            loopChecked: true,
            timestamp: now,
          },
        };
      }
    }

    // 2. Idempotency deduplication check
    const explicitIdempKey =
      args['idempotency_key'] ||
      args['idempotencyKey'] ||
      args['idempotencyToken'] ||
      args['client_request_token'] ||
      args['client_msg_id'] ||
      args['request_id'];

    let idempKey = explicitIdempKey;
    let isFingerprintFallback = false;

    // RFC 8785 SHA256 fallback when explicit key is omitted (prevents double-charge on un-keyed mutation calls)
    if (!idempKey && this.options.idempotency && toolName && this.options.autoFingerprintFallback !== false) {
      const cleanArgs = sanitizeArgsForHash(args);
      const canonicalArgs = canonicalizeJson(cleanArgs);
      const hash = crypto.createHash('sha256').update(`${toolName}:${canonicalArgs}`).digest('hex');
      idempKey = `fp_${hash}`;
      isFingerprintFallback = true;
    }

    if (this.options.idempotency && idempKey && toolName) {
      const cacheKey = `idemp:${toolName}:${idempKey}`;
      const cachedResponse = await this.storage.get(cacheKey);

      if (cachedResponse) {
        this.metrics.deduplicatedCalls++;
        this.emitSpan(toolName, 'DEDUPLICATED', now, false, { cached: true, idempotencyKey: String(idempKey) });
        return {
          ...cachedResponse,
          _shield: {
            ...cachedResponse._shield,
            cached: true,
            fingerprintDedup: isFingerprintFallback,
            idempotencyKey: idempKey,
            timestamp: now,
          },
        };
      }

      if (this.inFlightRequests.has(cacheKey)) {
        this.metrics.deduplicatedCalls++;
        const inFlightRes = await this.inFlightRequests.get(cacheKey)!;
        this.emitSpan(toolName, 'DEDUPLICATED', now, false, { singleflight: true, idempotencyKey: String(idempKey) });
        return {
          ...inFlightRes,
          _shield: {
            ...inFlightRes._shield,
            cached: true,
            fingerprintDedup: isFingerprintFallback,
            idempotencyKey: idempKey,
            timestamp: now,
          },
        };
      }

      const executionPromise = (async () => {
        let lockAcquired = false;
        try {
          if (this.storage.acquireLock) {
            try {
              lockAcquired = await this.storage.acquireLock(cacheKey, this.options.idempotencyTtlMs || 30000);
            } catch (err: any) {
              if (this.options.failClosed) {
                return {
                  isError: true,
                  content: [
                    {
                      type: 'text',
                      text: `[ToolVeto Shield Veto] Storage failure while acquiring idempotency lock for '${idempKey}': ${err?.message || 'Service Unavailable'}. Fail-closed strict policy enforced.`,
                    },
                  ],
                  _shield: {
                    idempotencyKey: idempKey,
                    timestamp: now,
                  },
                };
              }
              // Standard mode: ignore lock error, proceed fail-open
            }

            if (!lockAcquired && this.options.failClosed) {
              return {
                isError: true,
                content: [
                  {
                    type: 'text',
                    text: `[ToolVeto Shield Veto] Concurrent execution lock could not be acquired for idempotency key '${idempKey}'. Fail-closed strict policy enforced.`,
                  },
                ],
                _shield: {
                  idempotencyKey: idempKey,
                  timestamp: now,
                },
              };
            }
          }

          const res = await next(req);
          // Never cache error responses or intermediate 'input_required' task responses for 24h
          const isInputRequired = res.resultType === 'input_required';
          if (!res.isError && !isInputRequired) {
            const ttl = this.options.idempotencyTtlMs || 24 * 60 * 60 * 1000; // default 24h
            await this.storage.set(cacheKey, res, ttl);
          }
          return res;
        } finally {
          if (lockAcquired && this.storage.releaseLock) {
            try {
              await this.storage.releaseLock(cacheKey);
            } catch {
              // Ignore release errors
            }
          }
          this.inFlightRequests.delete(cacheKey);
        }
      })();

      this.inFlightRequests.set(cacheKey, executionPromise);
      const completedRes = await executionPromise;
      this.emitSpan(toolName, 'PASS', now, Boolean(completedRes.isError), { idempotencyKey: String(idempKey) });
      return completedRes;
    }

    // 3. Fallthrough execution to upstream MCP server
    const response = await next(req);

    // 4. Prompt Injection Scan on downstream output (cross-tool indirect injection defense)
    if (this.options.promptInjectionScan && this.options.promptInjectionScan.scanOutput !== false && response.content) {
      const action = this.options.promptInjectionScan.action || 'block';
      const patterns = [
        ...DEFAULT_PROMPT_INJECTION_PATTERNS,
        ...(this.options.promptInjectionScan.customPatterns || []),
      ];

      for (const item of response.content) {
        if (item.type === 'text' && item.text) {
          const outCheck = detectInjectionInString(item.text, patterns);
          if (outCheck.detected) {
            this.metrics.promptInjectionsDetected++;

            if (action === 'block') {
              this.metrics.promptInjectionsBlocked++;
              this.emitSpan(toolName, 'INJECTION_BLOCKED', now, true, { direction: 'output' });
              return {
                isError: true,
                content: [
                  {
                    type: 'text',
                    text: `[ToolVeto Shield Veto] Indirect prompt injection detected in output from tool '${toolName}': "${outCheck.match}". Downstream payload blocked to prevent agent hijacking.`,
                  },
                ],
                _shield: {
                  promptInjectionDetected: true,
                  promptInjectionAction: 'block',
                  timestamp: now,
                },
              };
            } else if (action === 'sanitize') {
              item.text = sanitizeText(item.text, patterns);
              response._shield = {
                ...response._shield,
                promptInjectionDetected: true,
                promptInjectionAction: 'sanitize',
              };
            } else if (action === 'flag') {
              response._shield = {
                ...response._shield,
                promptInjectionDetected: true,
                promptInjectionAction: 'flag',
              };
            }
          }
        }
      }
    }

    // 5. Cumulative Token Budget / Context Bomb Truncation across all content items
    if (this.options.tokenBudget && response.content && Array.isArray(response.content)) {
      const maxChars = this.options.tokenBudget * 4;
      let cumulativeChars = 0;
      let truncatedOccurred = false;
      let generatedCursor: string | undefined;
      const budgetCappedContent: Array<{ type: string; text?: string; [key: string]: any }> = [];

      for (let i = 0; i < response.content.length; i++) {
        const item = response.content[i];
        if (item.type === 'text' && typeof item.text === 'string') {
          const itemLen = item.text.length;
          if (cumulativeChars + itemLen <= maxChars) {
            cumulativeChars += itemLen;
            budgetCappedContent.push(item);
          } else {
            const allowedForThisItem = Math.max(0, maxChars - cumulativeChars);
            this.metrics.payloadsTruncated++;
            truncatedOccurred = true;

            // Inspect if content is structured JSON (records / items array)
            let structuredHandled = false;
            try {
              const parsed = JSON.parse(item.text);
              if (Array.isArray(parsed)) {
                const totalRecords = parsed.length;
                const sampleItemChars = Math.max(1, Math.round(itemLen / totalRecords));
                const itemsToKeep = Math.max(1, Math.min(totalRecords - 1, Math.floor(allowedForThisItem / sampleItemChars)));
                const slicedItems = parsed.slice(0, itemsToKeep);

                const cursorPayload = { tName: toolName, o: itemsToKeep, t: totalRecords };
                const encodedPayload = Buffer.from(JSON.stringify(cursorPayload)).toString('base64url');
                generatedCursor = `cur_${encodedPayload}`;
                this.cursorStore.set(generatedCursor, {
                  toolName: toolName || 'unknown',
                  offset: itemsToKeep,
                  total: totalRecords,
                  pageSize: itemsToKeep,
                  records: parsed,
                  createdAt: now,
                });

                const structuredEnvelope = {
                  truncated: true,
                  total_records: totalRecords,
                  items_returned: slicedItems.length,
                  next_cursor: generatedCursor,
                  records: slicedItems,
                  note: `[ToolVeto Shield: Truncated to prevent context exhaustion. Budget of ${this.options.tokenBudget} tokens (${maxChars} chars) reached. Subsequent items discarded.]`,
                };
                budgetCappedContent.push({
                  ...item,
                  text: JSON.stringify(structuredEnvelope, null, 2),
                });
                structuredHandled = true;
              } else if (parsed && typeof parsed === 'object') {
                const arrayKey = Object.keys(parsed).find((k) => Array.isArray(parsed[k]));
                if (arrayKey) {
                  const arr = parsed[arrayKey];
                  const totalRecords = arr.length;
                  const sampleItemChars = Math.max(1, Math.round(itemLen / totalRecords));
                  const itemsToKeep = Math.max(1, Math.min(totalRecords - 1, Math.floor(allowedForThisItem / sampleItemChars)));
                  const slicedItems = arr.slice(0, itemsToKeep);

                  const cursorPayload = { tName: toolName, o: itemsToKeep, t: totalRecords };
                  const encodedPayload = Buffer.from(JSON.stringify(cursorPayload)).toString('base64url');
                  generatedCursor = `cur_${encodedPayload}`;
                  const envelopeBase = { ...parsed };
                  delete envelopeBase[arrayKey];
                  this.cursorStore.set(generatedCursor, {
                    toolName: toolName || 'unknown',
                    offset: itemsToKeep,
                    total: totalRecords,
                    pageSize: itemsToKeep,
                    records: arr,
                    arrayKey,
                    envelopeBase,
                    createdAt: now,
                  });

                  const structuredEnvelope = {
                    ...parsed,
                    [arrayKey]: slicedItems,
                    truncated: true,
                    total_records: totalRecords,
                    items_returned: slicedItems.length,
                    next_cursor: generatedCursor,
                    note: `[ToolVeto Shield: Truncated to prevent context exhaustion. Budget of ${this.options.tokenBudget} tokens (${maxChars} chars) reached. Subsequent items discarded.]`,
                  };
                  budgetCappedContent.push({
                    ...item,
                    text: JSON.stringify(structuredEnvelope, null, 2),
                  });
                  structuredHandled = true;
                }
              }
            } catch {
              // Not structured JSON
            }

            if (!structuredHandled) {
              const noticeHeader = `\n\n[ToolVeto Shield: Truncated to prevent context exhaustion. Budget of ${this.options.tokenBudget} tokens (${maxChars} chars) reached.]\n`;
              const roughNoticeLen = noticeHeader.length + 180;
              const textSliceLen = Math.max(1, allowedForThisItem > roughNoticeLen ? allowedForThisItem - roughNoticeLen : Math.floor(allowedForThisItem / 2));

              const charPayload = { tName: toolName, c: textSliceLen, tc: itemLen };
              const encodedCharPayload = Buffer.from(JSON.stringify(charPayload)).toString('base64url');
              generatedCursor = `cur_${encodedCharPayload}`;
              this.cursorStore.set(generatedCursor, {
                toolName: toolName || 'unknown',
                charOffset: textSliceLen,
                totalChars: itemLen,
                charPageSize: textSliceLen,
                fullText: item.text,
                createdAt: now,
              });

              const envelopeMetadata = {
                truncated: true,
                total_characters: itemLen,
                characters_returned: textSliceLen,
                next_cursor: generatedCursor,
              };
              const notice = `${noticeHeader}${JSON.stringify(envelopeMetadata)}`;
              budgetCappedContent.push({
                ...item,
                text: item.text.slice(0, textSliceLen) + notice,
              });
            }

            cumulativeChars = maxChars;
            break;
          }
        } else {
          budgetCappedContent.push(item);
        }
      }

      if (truncatedOccurred) {
        response.content = budgetCappedContent as Array<{ type: string; text: string }>;
        response._shield = {
          ...response._shield,
          truncated: true,
          nextCursor: generatedCursor,
        };
        this.emitSpan(toolName, 'BUDGET_TRUNCATED', now, false, { nextCursor: generatedCursor || '' });
        return response;
      }
    }

    this.emitSpan(toolName, 'PASS', now, Boolean(response.isError));
    return response;
  }
}

export function shield<T extends object>(server: T, options: ShieldOptions): T {
  const middleware = new ShieldMiddleware(options);
  return new Proxy(server, {
    get(target, prop, receiver) {
      if (prop === '__shieldMiddleware') {
        return middleware;
      }
      const orig = Reflect.get(target, prop, receiver);
      if (typeof orig === 'function') {
        if (prop === 'handleCallTool' || prop === 'callTool') {
          return async (...args: any[]) => {
            return middleware.intercept(args[0], async (req) => orig.apply(target, [req]));
          };
        }
        if (prop === 'setRequestHandler') {
          return (schema: any, handler: (...hArgs: any[]) => Promise<any>) => {
            const schemaMethod =
              typeof schema === 'string'
                ? schema
                : schema?.method ||
                  schema?.shape?.method?.value ||
                  schema?.shape?.method?._def?.value;
            const isToolsCall = schemaMethod === 'tools/call';
            const wrappedHandler = async (request: any, extra?: any) => {
              if (isToolsCall || request?.method === 'tools/call') {
                return middleware.intercept(request, async (req) => handler(req, extra));
              }
              return handler(request, extra);
            };
            return orig.apply(target, [schema, wrappedHandler]);
          };
        }
        if (prop === 'tool' || prop === 'registerTool') {
          return (...args: any[]) => {
            const toolName = typeof args[0] === 'string' ? args[0] : 'unknown_tool';
            const lastIdx = args.length - 1;
            if (lastIdx >= 1 && typeof args[lastIdx] === 'function') {
              const origCallback = args[lastIdx];
              const wrappedCallback = async (toolArgs: any, extra?: any) => {
                const req: McpCallRequest = {
                  method: 'tools/call',
                  params: {
                    name: toolName,
                    arguments: toolArgs && typeof toolArgs === 'object' ? toolArgs : {},
                    _meta: extra?._meta,
                  },
                };
                return middleware.intercept(req, async (r) => origCallback(r.params.arguments, extra));
              };
              const newArgs = [...args.slice(0, lastIdx), wrappedCallback];
              return orig.apply(target, newArgs);
            }
            return orig.apply(target, args);
          };
        }
      }
      return orig;
    },
  });
}

export const withToolVetoShield = shield;

export * from './stores/redis.js';
export * from './stores/postgres.js';


