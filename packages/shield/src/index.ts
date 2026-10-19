import crypto from 'crypto';
import { LRUCache } from 'lru-cache';

export type PromptInjectionAction = 'block' | 'sanitize' | 'flag';

export interface PromptInjectionScanOptions {
  action?: PromptInjectionAction; // default: 'block'
  customPatterns?: RegExp[];
  scanOutput?: boolean; // default: true
}

export interface ShieldPolicyOptions {
  requireDryRunForDestructive?: boolean;
  elicitOnDestructive?: boolean;
  blockedTools?: string[];
  maxLimit?: number;
}

export interface ShieldOptions {
  idempotency?: boolean | { enabled?: boolean; ttlSeconds?: number; ttlMs?: number };
  idempotencyTtlMs?: number;
  autoFingerprintFallback?: boolean; // default: true (RFC 8785 SHA256 fallback when explicit key omitted)
  autoFingerprintWindowMs?: number; // optional short coalescing window for un-keyed identical mutations
  autoKeyUnkeyedMutations?: boolean; // when true, generates unique auto_<uuid> for un-keyed mutations outside coalescing window
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
  policy?: ShieldPolicyOptions;
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
    policyBlocked?: boolean;
    timestamp?: number;
  };
}

export interface ShieldMetrics {
  totalCalls: number;
  duplicatesBlocked: number;
  deduplicatedCalls: number;
  loopsBroken: number;
  contextBombsTruncated: number;
  payloadsTruncated: number;
  injectionsBlocked: number;
  promptInjectionsDetected: number;
  promptInjectionsBlocked: number;
  policyBlocks: number;
  tokensSaved: number;
  estimatedDollarsSaved: number;
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
  private locks = new Map<string, number>();

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
    let history = this.callHistory.get(key);
    const windowStart = timestamp - windowMs;
    if (!history) {
      history = [timestamp];
      this.callHistory.set(key, history, { ttl: windowMs * 2 });
      return 1;
    }

    // Amortized O(1) front-pointer pruning on monotonic timestamps
    let firstValidIdx = 0;
    while (firstValidIdx < history.length && history[firstValidIdx] <= windowStart) {
      firstValidIdx++;
    }
    if (firstValidIdx > 0) {
      history.splice(0, firstValidIdx);
    }
    history.push(timestamp);
    this.callHistory.set(key, history, { ttl: windowMs * 2 });
    return history.length;
  }

  async acquireLock(key: string, ttlMs = 5000): Promise<boolean> {
    const now = Date.now();
    const existingExpiry = this.locks.get(key);
    if (existingExpiry !== undefined && existingExpiry > now) {
      return false;
    }
    if (this.locks.size > 10000) {
      const oldest = this.locks.keys().next().value;
      if (oldest !== undefined) this.locks.delete(oldest);
    }
    this.locks.set(key, now + ttlMs);
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

export function canonicalizeJson(value: any, visited = new WeakSet<object>(), depth = 0): string {
  if (depth > 32) {
    return '"[MAX_DEPTH]"';
  }
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value) ?? 'null';
  }
  if (visited.has(value)) {
    return '"[CIRCULAR]"';
  }
  visited.add(value);
  try {
    if (Array.isArray(value)) {
      return '[' + value.map((item) => canonicalizeJson(item, visited, depth + 1)).join(',') + ']';
    }
    const keys = Object.keys(value).sort();
    return (
      '{' +
      keys
        .filter((k) => value[k] !== undefined && typeof value[k] !== 'function' && typeof value[k] !== 'symbol')
        .map((k) => JSON.stringify(k) + ':' + canonicalizeJson(value[k], visited, depth + 1))
        .join(',') +
      '}'
    );
  } finally {
    visited.delete(value);
  }
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
  autoFingerprintWindowMs?: number;
  autoKeyUnkeyedMutations?: boolean;
  loopLimit?: { count: number; windowMs: number };
  tokenBudget?: number;
  promptInjectionScan?: PromptInjectionScanOptions;
  policy?: ShieldPolicyOptions;
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
    autoFingerprintWindowMs: opts.autoFingerprintWindowMs,
    autoKeyUnkeyedMutations: opts.autoKeyUnkeyedMutations,
    loopLimit,
    tokenBudget,
    promptInjectionScan: opts.promptInjectionScan,
    policy: opts.policy,
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

const DESTRUCTIVE_TOOL_PATTERN = /(delete|drop|remove|destroy|purge|transfer|charge|refund|revoke|terminate)/i;

export class ShieldMiddleware {
  private storage: ShieldStorage;
  private options: NormalizedShieldOptions;
  private inFlightRequests: Map<string, Promise<McpCallResponse>> = new Map();
  private cursorStore: LRUCache<string, CursorStoreEntry> = new LRUCache({
    max: 500,
    maxSize: 50 * 1024 * 1024, // 50 MB total cap
    sizeCalculation: (entry) => {
      if (entry.fullText) return Math.max(1, entry.fullText.length);
      if (entry.records) return Math.max(1, entry.records.length * 256);
      return 1024;
    },
    ttl: 15 * 60 * 1000,
  });
  private rugPulledTools: Set<string> = new Set();
  private listChangedUnverified = false;
  private metrics: ShieldMetrics = {
    totalCalls: 0,
    duplicatesBlocked: 0,
    deduplicatedCalls: 0,
    loopsBroken: 0,
    contextBombsTruncated: 0,
    payloadsTruncated: 0,
    injectionsBlocked: 0,
    promptInjectionsDetected: 0,
    promptInjectionsBlocked: 0,
    policyBlocks: 0,
    tokensSaved: 0,
    estimatedDollarsSaved: 0,
  };

  constructor(rawOptions: ShieldOptions = {}) {
    this.options = normalizeShieldOptions(rawOptions);
    this.storage = this.options.storage || new MemoryShieldStorage();
  }

  private recalculateDollarsSaved(): void {
    this.metrics.estimatedDollarsSaved = Number(
      (
        this.metrics.duplicatesBlocked * 50 +
        this.metrics.loopsBroken * 4.5 +
        (this.metrics.tokensSaved / 1000) * 0.015 +
        this.metrics.injectionsBlocked * 100
      ).toFixed(2)
    );
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
    this.recalculateDollarsSaved();
    return { ...this.metrics };
  }

  public async interceptCall(
    req: McpCallRequest,
    next: (req: McpCallRequest) => Promise<McpCallResponse>
  ): Promise<McpCallResponse> {
    return this.intercept(req, next);
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

    // -0.75. Inline Policy Enforcement
    if (this.options.policy && toolName) {
      if (this.options.policy.blockedTools?.includes(toolName)) {
        this.metrics.policyBlocks++;
        this.recalculateDollarsSaved();
        this.emitSpan(toolName, 'POLICY_BLOCKED', now, true, { reason: 'blocked_tool' });
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `[ToolVeto Shield Policy] Tool '${toolName}' is blocked by active security policy.`,
            },
          ],
          _shield: {
            policyBlocked: true,
            timestamp: now,
          },
        };
      }

      const isDestructive = DESTRUCTIVE_TOOL_PATTERN.test(toolName);
      if (
        this.options.policy.elicitOnDestructive &&
        isDestructive &&
        args?.dry_run !== true &&
        req.params?._meta?.confirmed !== true &&
        args?._meta?.confirmed !== true
      ) {
        this.metrics.policyBlocks++;
        this.recalculateDollarsSaved();
        this.emitSpan(toolName, 'POLICY_ELICIT', now, false, { reason: 'elicit_on_destructive' });
        return {
          resultType: 'input_required',
          taskId: `task_confirm_${toolName}_${Date.now()}`,
          content: [
            {
              type: 'text',
              text: `[ToolVeto Shield Policy] Destructive tool '${toolName}' requires explicit human confirmation (_meta.confirmed: true) or simulation mode (dry_run: true) before execution.`,
            },
          ],
          _shield: {
            policyBlocked: true,
            timestamp: now,
          },
        };
      }

      if (this.options.policy.requireDryRunForDestructive && isDestructive && args?.dry_run !== true) {
        this.metrics.policyBlocks++;
        this.recalculateDollarsSaved();
        this.emitSpan(toolName, 'POLICY_BLOCKED', now, true, { reason: 'require_dry_run' });
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `[ToolVeto Shield Policy] Destructive tool '${toolName}' must be called with 'dry_run: true' before executing live state mutations.`,
            },
          ],
          _shield: {
            policyBlocked: true,
            timestamp: now,
          },
        };
      }

      if (this.options.policy.maxLimit !== undefined && typeof args?.limit === 'number' && args.limit > this.options.policy.maxLimit) {
        args = { ...args, limit: this.options.policy.maxLimit };
        if (req.params) {
          req.params.arguments = args;
        }
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
          this.metrics.injectionsBlocked++;
          this.recalculateDollarsSaved();
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
        this.metrics.tokensSaved += 2000;
        this.recalculateDollarsSaved();
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

    // RFC 8785 SHA256 fallback when explicit key is omitted
    if (!idempKey && this.options.idempotency && toolName) {
      if (this.options.autoKeyUnkeyedMutations || this.options.autoFingerprintFallback === false) {
        idempKey = `auto_${crypto.randomUUID()}`;
        if (req.params) {
          req.params.arguments = { ...args, idempotency_key: idempKey };
          args = req.params.arguments;
        }
      } else {
        const cleanArgs = sanitizeArgsForHash(args);
        const canonicalArgs = canonicalizeJson(cleanArgs);
        const hash = crypto.createHash('sha256').update(`${toolName}:${canonicalArgs}`).digest('hex');
        idempKey = `fp_${hash}`;
        isFingerprintFallback = true;
      }
    }

    const executeDownstream = async (): Promise<{ response: McpCallResponse; postAction?: string; nextCursor?: string }> => {
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
                this.metrics.injectionsBlocked++;
                this.recalculateDollarsSaved();
                return {
                  postAction: 'INJECTION_BLOCKED',
                  response: {
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
        const totalOriginalChars = response.content.reduce(
          (sum, it) => sum + (it.type === 'text' && typeof it.text === 'string' ? it.text.length : 0),
          0
        );
        const originalTokens = Math.ceil(totalOriginalChars / 4);
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
                  const maxStoredRecords = Math.min(parsed.length, 1000);
                  this.cursorStore.set(generatedCursor, {
                    toolName: toolName || 'unknown',
                    offset: itemsToKeep,
                    total: totalRecords,
                    pageSize: itemsToKeep,
                    records: parsed.slice(0, maxStoredRecords),
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
                    const maxStoredRecords = Math.min(arr.length, 1000);
                    this.cursorStore.set(generatedCursor, {
                      toolName: toolName || 'unknown',
                      offset: itemsToKeep,
                      total: totalRecords,
                      pageSize: itemsToKeep,
                      records: arr.slice(0, maxStoredRecords),
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
                const maxStoredChars = Math.min(item.text.length, 262144);
                this.cursorStore.set(generatedCursor, {
                  toolName: toolName || 'unknown',
                  charOffset: textSliceLen,
                  totalChars: itemLen,
                  charPageSize: textSliceLen,
                  fullText: item.text.slice(0, maxStoredChars),
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
          this.metrics.contextBombsTruncated++;
          this.metrics.tokensSaved += Math.max(0, originalTokens - this.options.tokenBudget);
          this.recalculateDollarsSaved();
          response.content = budgetCappedContent as Array<{ type: string; text: string }>;
          response._shield = {
            ...response._shield,
            truncated: true,
            nextCursor: generatedCursor,
          };
          return {
            response,
            postAction: 'BUDGET_TRUNCATED',
            nextCursor: generatedCursor,
          };
        }
      }

      return { response };
    };

    if (this.options.idempotency && idempKey && toolName) {
      const cacheKey = `idemp:${toolName}:${idempKey}`;
      const cachedResponse = await this.storage.get(cacheKey);

      if (cachedResponse) {
        this.metrics.deduplicatedCalls++;
        this.metrics.duplicatesBlocked++;
        this.recalculateDollarsSaved();
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
        this.metrics.duplicatesBlocked++;
        this.recalculateDollarsSaved();
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
              lockAcquired = await this.storage.acquireLock(cacheKey, this.options.idempotencyTtlMs || 5000);
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

          const { response: res, postAction, nextCursor } = await executeDownstream();
          if (postAction === 'INJECTION_BLOCKED') {
            this.emitSpan(toolName, 'INJECTION_BLOCKED', now, true, { direction: 'output' });
          } else if (postAction === 'BUDGET_TRUNCATED') {
            this.emitSpan(toolName, 'BUDGET_TRUNCATED', now, false, { nextCursor: nextCursor || '' });
          }
          // Never cache error responses or intermediate 'input_required' task responses for 24h
          const isInputRequired = res.resultType === 'input_required';
          if (!res.isError && !isInputRequired) {
            const ttl = isFingerprintFallback
              ? (this.options.autoFingerprintWindowMs ?? this.options.idempotencyTtlMs ?? 2000)
              : (this.options.idempotencyTtlMs || 24 * 60 * 60 * 1000); // default 24h for explicit keys, 2s coalescing window for un-keyed fingerprint
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
    const { response, postAction, nextCursor } = await executeDownstream();
    if (postAction === 'INJECTION_BLOCKED') {
      this.emitSpan(toolName, 'INJECTION_BLOCKED', now, true, { direction: 'output' });
      return response;
    }
    if (postAction === 'BUDGET_TRUNCATED') {
      this.emitSpan(toolName, 'BUDGET_TRUNCATED', now, false, { nextCursor: nextCursor || '' });
      return response;
    }

    this.emitSpan(toolName, 'PASS', now, Boolean(response.isError));
    return response;
  }
}

export { ShieldMiddleware as ToolVetoShield };

export function shield<T extends object>(server: T, options: ShieldOptions = {}): T {
  const middleware = new ShieldMiddleware(options);
  return new Proxy(server, {
    get(target, prop, receiver) {
      if (prop === '__shieldMiddleware') {
        return middleware;
      }
      if (prop === '__shieldMetrics') {
        return middleware.getMetrics();
      }
      if (prop === 'getShieldMetrics' || prop === 'getMetrics') {
        return () => middleware.getMetrics();
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


