import { ShieldStorage, McpCallResponse } from '../index.js';

export interface RedisClientLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, mode?: string, duration?: number, flag?: string): Promise<unknown>;
  del?(key: string): Promise<number>;
  eval?(script: string, numkeys: number, ...args: (string | number)[]): Promise<unknown>;
  evalsha?(sha: string, numkeys: number, ...args: (string | number)[]): Promise<unknown>;
  zremrangebyscore?(key: string, min: number | string, max: number | string): Promise<number>;
  zadd?(key: string, score: number, member: string): Promise<number>;
  zcard?(key: string): Promise<number>;
  expire?(key: string, seconds: number): Promise<number>;
}

export interface RedisShieldStorageOptions {
  mode?: 'strict' | 'standard'; // 'strict' = fail-closed (-32001), 'standard' = fail-open with SHIELD_DEDUP_DEGRADED
  onDegraded?: (reason: string, error?: unknown) => void;
}

export class RedisShieldStorage implements ShieldStorage {
  private fallbackSlidingWindows = new Map<string, number[]>();

  constructor(
    private redis: RedisClientLike,
    private options: RedisShieldStorageOptions = {}
  ) {}

  async get(key: string): Promise<McpCallResponse | undefined> {
    const raw = await this.redis.get(`shield:cache:${key}`);
    if (!raw) return undefined;
    try {
      return JSON.parse(raw);
    } catch {
      return undefined;
    }
  }

  async set(key: string, value: McpCallResponse, ttlMs?: number): Promise<void> {
    const serialized = JSON.stringify(value);
    if (ttlMs) {
      await this.redis.set(`shield:cache:${key}`, serialized, 'PX', ttlMs);
    } else {
      await this.redis.set(`shield:cache:${key}`, serialized);
    }
  }

  async recordCall(key: string, timestamp: number, windowMs: number): Promise<number> {
    const redisKey = `shield:loop:${key}`;
    const windowStart = timestamp - windowMs;
    const expireSec = Math.ceil(windowMs / 1000) * 2;
    const member = `${timestamp}-${Math.random().toString(36).slice(2, 7)}`;

    // 1. Atomic Lua script via EVAL if available on Redis client (prevents burst race conditions)
    if (typeof (this.redis as any).eval === 'function') {
      try {
        const luaScript = `
          local key = KEYS[1]
          local wStart = tonumber(ARGV[1])
          local now = tonumber(ARGV[2])
          local mem = ARGV[3]
          local expSec = tonumber(ARGV[4])
          redis.call('ZREMRANGEBYSCORE', key, 0, wStart)
          redis.call('ZADD', key, now, mem)
          local count = redis.call('ZCARD', key)
          redis.call('EXPIRE', key, expSec)
          return count
        `;
        const res = await (this.redis as any).eval(luaScript, 1, redisKey, windowStart, timestamp, member, expireSec);
        return Number(res);
      } catch (err) {
        if (this.options.mode === 'strict') {
          throw new Error(`[ToolVeto Shield Strict] Redis EVAL sliding window failed: ${err instanceof Error ? err.message : String(err)}`);
        }
        if (this.options.onDegraded) {
          this.options.onDegraded('SHIELD_DEDUP_DEGRADED', err);
        }
      }
    }

    // 2. Multi-step ZSET fallback if zremrangebyscore/zadd/zcard exist
    if (this.redis.zremrangebyscore && this.redis.zadd && this.redis.zcard) {
      await this.redis.zremrangebyscore(redisKey, 0, windowStart);
      await this.redis.zadd(redisKey, timestamp, member);
      const count = await this.redis.zcard(redisKey);
      if (this.redis.expire) {
        await this.redis.expire(redisKey, expireSec);
      }
      return count;
    }

    // 3. Guaranteed sliding-window in-memory fallback (replaces inaccurate fixed-window INCR)
    const history = this.fallbackSlidingWindows.get(redisKey) || [];
    const valid = history.filter((t) => t > windowStart);
    valid.push(timestamp);
    this.fallbackSlidingWindows.set(redisKey, valid);
    return valid.length;
  }

  async acquireLock(key: string, ttlMs = 5000): Promise<boolean> {
    const lockKey = `shield:lock:${key}`;
    const isStrict = this.options.mode === 'strict';
    try {
      if (typeof (this.redis as any).set === 'function') {
        const res = await (this.redis as any).set(lockKey, 'locked', 'PX', ttlMs, 'NX');
        const acquired = res === 'OK' || res === true || res === 1;
        if (!acquired && isStrict) {
          const err: any = new Error(`[ToolVeto Shield Strict] Failed to acquire distributed lock for key '${key}'`);
          err.code = -32001;
          err.status = 503;
          throw err;
        }
        return acquired;
      }
    } catch (err) {
      if (isStrict) {
        if ((err as any)?.code === -32001) throw err;
        const strictErr: any = new Error(`[ToolVeto Shield Strict] Redis error during lock acquisition for key '${key}': ${err instanceof Error ? err.message : String(err)}`);
        strictErr.code = -32001;
        strictErr.status = 503;
        throw strictErr;
      }
      if (this.options.onDegraded) {
        this.options.onDegraded('SHIELD_DEDUP_DEGRADED', err);
      }
      return true; // Fail-open on standard mode
    }

    if (isStrict) {
      const err: any = new Error(`[ToolVeto Shield Strict] Redis client lacks atomic set NX capability for key '${key}'`);
      err.code = -32001;
      err.status = 503;
      throw err;
    }
    return true; // Fail-open on standard mode
  }

  async releaseLock(key: string): Promise<void> {
    const lockKey = `shield:lock:${key}`;
    try {
      if (typeof (this.redis as any).del === 'function') {
        await (this.redis as any).del(lockKey);
      }
    } catch {
      // Safe fallback
    }
  }
}
