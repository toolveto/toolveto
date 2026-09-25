import crypto from 'crypto';

export interface ShieldOptions {
  idempotency?: boolean;
  idempotencyTtlMs?: number;
  loopLimit?: {
    count: number;
    windowMs: number;
  };
  tokenBudget?: number;
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
    timestamp?: number;
  };
}

export interface ShieldMetrics {
  totalCalls: number;
  deduplicatedCalls: number;
  loopsBroken: number;
  payloadsTruncated: number;
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

export class ShieldMiddleware {
  private storage: ShieldStorage;
  private metrics: ShieldMetrics = {
    totalCalls: 0,
    deduplicatedCalls: 0,
    loopsBroken: 0,
    payloadsTruncated: 0,
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
    const args = req.params?.arguments || {};
    const agentId = req.params?._meta?.agentId || 'default-agent';

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

    // 4. Token Budget / Context Bomb Truncation
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

