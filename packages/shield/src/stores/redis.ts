import { ShieldStorage, McpCallResponse } from '../index.js';

export interface RedisClientLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, mode?: string, duration?: number): Promise<unknown>;
  zremrangebyscore?(key: string, min: number | string, max: number | string): Promise<number>;
  zadd?(key: string, score: number, member: string): Promise<number>;
  zcard?(key: string): Promise<number>;
  expire?(key: string, seconds: number): Promise<number>;
}

export class RedisShieldStorage implements ShieldStorage {
  constructor(private redis: RedisClientLike) {}

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

    // If client supports Redis Sorted Sets (atomic sliding window)
    if (this.redis.zremrangebyscore && this.redis.zadd && this.redis.zcard) {
      await this.redis.zremrangebyscore(redisKey, 0, windowStart);
      const member = `${timestamp}-${Math.random().toString(36).slice(2, 7)}`;
      await this.redis.zadd(redisKey, timestamp, member);
      const count = await this.redis.zcard(redisKey);
      if (this.redis.expire) {
        await this.redis.expire(redisKey, Math.ceil(windowMs / 1000) * 2);
      }
      return count;
    }

    // Fallback using simple counter if ZSET is not available
    const raw = await this.redis.get(redisKey);
    const count = (raw ? parseInt(raw, 10) : 0) + 1;
    await this.redis.set(redisKey, count.toString(), 'PX', windowMs);
    return count;
  }
}
