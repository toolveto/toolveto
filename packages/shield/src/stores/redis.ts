import { LRUCache } from 'lru-cache';
import { ShieldStorage, McpCallResponse } from '../index.js';

export interface RedisPipelineLike {
  zremrangebyscore(key: string, min: number | string, max: number | string): this;
  zadd(key: string, score: number, member: string): this;
  zcard(key: string): this;
  expire(key: string, seconds: number): this;
  exec(): Promise<Array<[Error | null, unknown]> | unknown[] | null>;
}

export interface RedisClientLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, mode?: string, duration?: number, flag?: string): Promise<unknown>;
  del?(key: string): Promise<number>;
  eval?(script: string, numkeys: number, ...args: (string | number)[]): Promise<unknown>;
  evalsha?(sha: string, numkeys: number, ...args: (string | number)[]): Promise<unknown>;
  multi?(): RedisPipelineLike;
  pipeline?(): RedisPipelineLike;
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
  private fallbackSlidingWindows = new LRUCache<string, number[]>({
    max: 10000,
    ttl: 10 * 60 * 1000,
  });

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

    // 2. Atomic MULTI/EXEC or pipeline fallback if supported on Redis client
    const txFactory =
      typeof this.redis.multi === 'function'
        ? () => this.redis.multi!()
        : typeof this.redis.pipeline === 'function'
          ? () => this.redis.pipeline!()
          : null;
    if (txFactory) {
      try {
        const tx = txFactory();
        tx.zremrangebyscore(redisKey, 0, windowStart);
        tx.zadd(redisKey, timestamp, member);
        tx.zcard(redisKey);
        tx.expire(redisKey, expireSec);
        const execRes = await tx.exec();
        if (Array.isArray(execRes) && execRes.length >= 3) {
          const zcardEntry = execRes[2];
          const countVal = Array.isArray(zcardEntry) ? zcardEntry[1] : zcardEntry;
          if (typeof countVal === 'number') {
            return countVal;
          }
        }
      } catch (err) {
        if (this.options.mode === 'strict') {
          throw new Error(`[ToolVeto Shield Strict] Redis pipeline sliding window failed: ${err instanceof Error ? err.message : String(err)}`);
        }
        if (this.options.onDegraded) {
          this.options.onDegraded('SHIELD_DEDUP_DEGRADED', err);
        }
      }
    }

    // 3. Multi-step ZSET fallback if zremrangebyscore/zadd/zcard exist
    if (this.redis.zremrangebyscore && this.redis.zadd && this.redis.zcard) {
      await this.redis.zremrangebyscore(redisKey, 0, windowStart);
      await this.redis.zadd(redisKey, timestamp, member);
      const count = await this.redis.zcard(redisKey);
      if (this.redis.expire) {
        await this.redis.expire(redisKey, expireSec);
      }
      return count;
    }

    // 4. Guaranteed bounded sliding-window in-memory fallback with amortized O(1) front pruning
    let history = this.fallbackSlidingWindows.get(redisKey);
    if (!history) {
      history = [timestamp];
      this.fallbackSlidingWindows.set(redisKey, history, { ttl: windowMs * 2 });
      return 1;
    }
    let firstValid = 0;
    while (firstValid < history.length && history[firstValid] <= windowStart) {
      firstValid++;
    }
    if (firstValid > 0) {
      history.splice(0, firstValid);
    }
    history.push(timestamp);
    this.fallbackSlidingWindows.set(redisKey, history, { ttl: windowMs * 2 });
    return history.length;
  }

  async acquireLock(key: string, ttlMs = 5000): Promise<boolean> {
    const lockKey = `shield:lock:${key}`;
    const isStrict = this.options.mode === 'strict';
    try {
      if (typeof (this.redis as any).eval === 'function') {
        const luaLock = `
          if redis.call('SET', KEYS[1], 'locked', 'PX', tonumber(ARGV[1]), 'NX') then
            return 1
          end
          return 0
        `;
        const res = await (this.redis as any).eval(luaLock, 1, lockKey, ttlMs);
        const acquired = res === 1 || res === true || res === 'OK';
        if (!acquired && isStrict) {
          const err: any = new Error(`[ToolVeto Shield Strict] Failed to acquire distributed lock for key '${key}'`);
          err.code = -32001;
          err.status = 503;
          throw err;
        }
        return acquired;
      }
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
