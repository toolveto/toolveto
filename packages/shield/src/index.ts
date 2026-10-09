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

  async clear(): Promise<void> {
    this.cache.clear();
    this.callHistory.clear();
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

export class ShieldMiddleware {
  private storage: ShieldStorage;
  private inFlightRequests: Map<string, Promise<McpCallResponse>> = new Map();
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
      const canonicalArgs = canonicalizeJson(args);
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
      const canonicalArgs = canonicalizeJson(args);
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
        try {
          const res = await next(req);
          // Never cache error responses for 24h (only cache successful non-error responses)
          if (!res.isError) {
            const ttl = this.options.idempotencyTtlMs || 24 * 60 * 60 * 1000; // default 24h
            await this.storage.set(cacheKey, res, ttl);
          }
          return res;
        } finally {
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

            const cursorHash = crypto.createHash('sha256').update(`${toolName}:${allowedForThisItem}:${now}`).digest('hex').slice(0, 8);
            generatedCursor = `cur_${cursorHash}`;

            // Inspect if content is structured JSON (records / items array)
            let structuredHandled = false;
            try {
              const parsed = JSON.parse(item.text);
              if (Array.isArray(parsed)) {
                const totalRecords = parsed.length;
                const sampleItemChars = Math.max(1, Math.round(itemLen / totalRecords));
                const itemsToKeep = Math.max(1, Math.min(totalRecords - 1, Math.floor(allowedForThisItem / sampleItemChars)));
                const slicedItems = parsed.slice(0, itemsToKeep);
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
              const estimatedTotal = Math.max(2, Math.round(itemLen / 40));
              const estimatedReturned = Math.max(1, Math.round(allowedForThisItem / 40));
              const envelopeMetadata = {
                truncated: true,
                total_records: estimatedTotal,
                items_returned: estimatedReturned,
                next_cursor: generatedCursor,
              };
              const notice = `\n\n${JSON.stringify(envelopeMetadata)}\n[ToolVeto Shield: Truncated to prevent context exhaustion. Budget of ${this.options.tokenBudget} tokens (${maxChars} chars) reached. Next cursor: ${generatedCursor}. Subsequent items discarded.]`;
              const textSliceLen = Math.max(0, allowedForThisItem - Math.min(allowedForThisItem, 180));
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


