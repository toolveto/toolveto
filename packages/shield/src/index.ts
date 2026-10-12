import crypto from 'crypto';
import { LRUCache } from 'lru-cache';

export type PromptInjectionAction = 'block' | 'sanitize' | 'flag';

export interface PromptInjectionScanOptions {
  action?: PromptInjectionAction; // default: 'block'
  customPatterns?: RegExp[];
  scanOutput?: boolean; // default: true
}

export interface ShieldOptions {
  idempotency?: boolean;
  idempotencyTtlMs?: number;
  autoFingerprintFallback?: boolean; // default: true (RFC 8785 SHA256 fallback when explicit key omitted)
  loopLimit?: {
    count: number;
    windowMs: number;
  };
  tokenBudget?: number;
  promptInjectionScan?: PromptInjectionScanOptions;
  storage?: ShieldStorage;
  failClosed?: boolean; // default: false (fail-open standard mode, true = strict fail-closed)
  onSpan?: (span: ShieldSpan) => void; // OpenTelemetry span emission hook
}

export interface ShieldSpan {
  traceId: string;
  spanId: string;
  name: string;
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

export class ShieldMiddleware {
  private storage: ShieldStorage;
  private inFlightRequests: Map<string, Promise<McpCallResponse>> = new Map();
  private cursorStore: LRUCache<string, { toolName: string; offset?: number; total?: number; charOffset?: number; totalChars?: number; createdAt: number }> = new LRUCache({ max: 5000 });
  private metrics: ShieldMetrics = {
    totalCalls: 0,
    deduplicatedCalls: 0,
    loopsBroken: 0,
    payloadsTruncated: 0,
    promptInjectionsDetected: 0,
    promptInjectionsBlocked: 0,
  };

  constructor(private options: ShieldOptions) {
    this.storage = options.storage || new MemoryShieldStorage();
  }

  public resolveCursor(cursor: string): { toolName?: string; offset?: number; total?: number; charOffset?: number; totalChars?: number } | null {
    if (!cursor || typeof cursor !== 'string' || !cursor.startsWith('cur_')) return null;
    const fromStore = this.cursorStore.get(cursor);
    if (fromStore) return fromStore;
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
      return await executionPromise;
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
                  this.cursorStore.set(generatedCursor, {
                    toolName: toolName || 'unknown',
                    offset: itemsToKeep,
                    total: totalRecords,
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
      }
    }

    return response;
  }
}

export function shield<T extends object>(server: T, options: ShieldOptions): T {
  const middleware = new ShieldMiddleware(options);
  return new Proxy(server, {
    get(target, prop, receiver) {
      const orig = Reflect.get(target, prop, receiver);
      if (typeof orig === 'function' && (prop === 'handleCallTool' || prop === 'callTool')) {
        return async (...args: any[]) => {
          return middleware.intercept(args[0], async (req) => orig.apply(target, [req]));
        };
      }
      return orig;
    },
  });
}

export * from './stores/redis.js';
export * from './stores/postgres.js';


