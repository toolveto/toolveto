import crypto from 'crypto';

export type PromptInjectionAction = 'block' | 'sanitize' | 'flag';

export interface PromptInjectionScanOptions {
  action?: PromptInjectionAction; // default: 'block'
  customPatterns?: RegExp[];
  scanOutput?: boolean; // default: true
}

export interface ShieldOptions {
  idempotency?: boolean;
  idempotencyTtlMs?: number;
  loopLimit?: {
    count: number;
    windowMs: number;
  };
  tokenBudget?: number;
  promptInjectionScan?: PromptInjectionScanOptions;
  storage?: ShieldStorage;
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
  clear?(): Promise<void>;
}

export class MemoryShieldStorage implements ShieldStorage {
  private cache: Map<string, { value: McpCallResponse; expiresAt?: number }> = new Map();
  private callHistory: Map<string, number[]> = new Map();

  async get(key: string): Promise<McpCallResponse | undefined> {
    const item = this.cache.get(key);
    if (!item) return undefined;
    if (item.expiresAt && Date.now() > item.expiresAt) {
      this.cache.delete(key);
      return undefined;
    }
    return item.value;
  }

  async set(key: string, value: McpCallResponse, ttlMs?: number): Promise<void> {
    this.cache.set(key, {
      value,
      expiresAt: ttlMs ? Date.now() + ttlMs : undefined,
    });
  }

  async recordCall(key: string, timestamp: number, windowMs: number): Promise<number> {
    const history = this.callHistory.get(key) || [];
    const windowStart = timestamp - windowMs;
    const recent = history.filter((t) => t > windowStart);
    recent.push(timestamp);
    this.callHistory.set(key, recent);
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
  patterns: RegExp[]
): { detected: boolean; match?: string } {
  if (typeof obj === 'string') {
    return detectInjectionInString(obj, patterns);
  }
  if (Array.isArray(obj)) {
    for (const item of obj) {
      const res = scanObjectForInjection(item, patterns);
      if (res.detected) return res;
    }
  } else if (obj && typeof obj === 'object') {
    for (const val of Object.values(obj)) {
      const res = scanObjectForInjection(val, patterns);
      if (res.detected) return res;
    }
  }
  return { detected: false };
}

function sanitizeObject(obj: any, patterns: RegExp[]): any {
  if (typeof obj === 'string') {
    return sanitizeText(obj, patterns);
  }
  if (Array.isArray(obj)) {
    return obj.map((item) => sanitizeObject(item, patterns));
  }
  if (obj && typeof obj === 'object') {
    const res: Record<string, any> = {};
    for (const [k, v] of Object.entries(obj)) {
      res[k] = sanitizeObject(v, patterns);
    }
    return res;
  }
  return obj;
}

export class ShieldMiddleware {
  private storage: ShieldStorage;
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
      const argsHash = crypto.createHash('sha256').update(JSON.stringify(args)).digest('hex').slice(0, 12);
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
    const idempKey =
      args['idempotency_key'] ||
      args['idempotencyKey'] ||
      args['idempotencyToken'] ||
      args['client_request_token'] ||
      args['client_msg_id'] ||
      args['request_id'];

    if (this.options.idempotency && idempKey && toolName) {
      const cacheKey = `idemp:${toolName}:${idempKey}`;
      const cachedResponse = await this.storage.get(cacheKey);

      if (cachedResponse) {
        this.metrics.deduplicatedCalls++;
        return {
          ...cachedResponse,
          _shield: {
            cached: true,
            timestamp: now,
          },
        };
      }

      const response = await next(req);
      const ttl = this.options.idempotencyTtlMs || 24 * 60 * 60 * 1000; // default 24h
      await this.storage.set(cacheKey, response, ttl);
      return response;
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

    // 5. Token Budget / Context Bomb Truncation
    if (this.options.tokenBudget && response.content) {
      const maxChars = this.options.tokenBudget * 4;
      for (const item of response.content) {
        if (item.type === 'text' && item.text && item.text.length > maxChars) {
          this.metrics.payloadsTruncated++;
          item.text =
            item.text.slice(0, maxChars) +
            `\n\n[ToolVeto Shield: Truncated to prevent context exhaustion. Truncated from ${item.text.length} chars to ${maxChars} chars. Use pagination limit/cursor parameters to retrieve next items.]`;
          response._shield = {
            ...response._shield,
            truncated: true,
          };
        }
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


