import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { Pool } from 'pg';
import { ShieldMiddleware } from '../index.js';
import { PostgresShieldStorage } from '../stores/postgres.js';
import { RedisShieldStorage, RedisClientLike } from '../stores/redis.js';

/**
 * Minimal zero-dependency RESP2 TCP client for live Redis integration verification.
 * Exercises real Redis 7 Lua `EVAL`, `GET`, `SET PX NX`, and `DEL` commands over TCP.
 */
class Resp2RedisClient implements RedisClientLike {
  private socket: net.Socket;
  private buffer: Buffer = Buffer.alloc(0);
  private pending: Array<{
    resolve: (val: any) => void;
    reject: (err: Error) => void;
  }> = [];

  private constructor(socket: net.Socket) {
    this.socket = socket;
    this.socket.on('data', (chunk: Buffer) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      this.drainResponses();
    });
    this.socket.on('error', (err) => {
      while (this.pending.length > 0) {
        this.pending.shift()?.reject(err);
      }
    });
  }

  static async connect(redisUrl: string): Promise<Resp2RedisClient> {
    const parsed = new URL(redisUrl);
    const host = parsed.hostname || '127.0.0.1';
    const port = Number(parsed.port || 6379);
    const socket = await new Promise<net.Socket>((resolve, reject) => {
      const s = net.createConnection({ host, port }, () => resolve(s));
      s.once('error', reject);
    });
    const client = new Resp2RedisClient(socket);
    if (parsed.password) {
      await client.sendCommand(['AUTH', decodeURIComponent(parsed.password)]);
    }
    return client;
  }

  private parseRespValue(offset = 0): { value: any; nextOffset: number } | null {
    if (offset >= this.buffer.length) return null;
    const prefix = String.fromCharCode(this.buffer[offset]);
    const lineEnd = this.buffer.indexOf('\r\n', offset);
    if (lineEnd === -1) return null;
    const header = this.buffer.subarray(offset + 1, lineEnd).toString('utf8');

    if (prefix === '+') {
      return { value: header, nextOffset: lineEnd + 2 };
    }
    if (prefix === '-') {
      return { value: new Error(header), nextOffset: lineEnd + 2 };
    }
    if (prefix === ':') {
      return { value: Number(header), nextOffset: lineEnd + 2 };
    }
    if (prefix === '$') {
      const len = Number(header);
      if (len === -1) {
        return { value: null, nextOffset: lineEnd + 2 };
      }
      const start = lineEnd + 2;
      const end = start + len;
      if (this.buffer.length < end + 2) return null;
      const str = this.buffer.subarray(start, end).toString('utf8');
      return { value: str, nextOffset: end + 2 };
    }
    if (prefix === '*') {
      const count = Number(header);
      if (count === -1) {
        return { value: null, nextOffset: lineEnd + 2 };
      }
      const arr: any[] = [];
      let cursor = lineEnd + 2;
      for (let i = 0; i < count; i++) {
        const elem = this.parseRespValue(cursor);
        if (!elem) return null;
        arr.push(elem.value);
        cursor = elem.nextOffset;
      }
      return { value: arr, nextOffset: cursor };
    }
    throw new Error(`Unsupported RESP2 prefix: ${prefix}`);
  }

  private drainResponses(): void {
    while (this.pending.length > 0) {
      const parsed = this.parseRespValue(0);
      if (!parsed) break;
      this.buffer = this.buffer.subarray(parsed.nextOffset);
      const waiter = this.pending.shift()!;
      if (parsed.value instanceof Error) {
        waiter.reject(parsed.value);
      } else {
        waiter.resolve(parsed.value);
      }
    }
  }

  sendCommand(args: Array<string | number>): Promise<any> {
    const parts: Buffer[] = [Buffer.from(`*${args.length}\r\n`, 'utf8')];
    for (const arg of args) {
      const str = String(arg);
      const byteLen = Buffer.byteLength(str, 'utf8');
      parts.push(Buffer.from(`$${byteLen}\r\n${str}\r\n`, 'utf8'));
    }
    const payload = Buffer.concat(parts);
    return new Promise((resolve, reject) => {
      this.pending.push({ resolve, reject });
      this.socket.write(payload);
    });
  }

  async get(key: string): Promise<string | null> {
    return this.sendCommand(['GET', key]);
  }

  async set(key: string, value: string, mode?: string, duration?: number, flag?: string): Promise<unknown> {
    const cmd: Array<string | number> = ['SET', key, value];
    if (mode && duration !== undefined) {
      cmd.push(mode, duration);
    }
    if (flag) {
      cmd.push(flag);
    }
    return this.sendCommand(cmd);
  }

  async del(key: string): Promise<number> {
    return this.sendCommand(['DEL', key]);
  }

  async eval(script: string, numkeys: number, ...args: (string | number)[]): Promise<unknown> {
    return this.sendCommand(['EVAL', script, numkeys, ...args]);
  }

  async close(): Promise<void> {
    await new Promise<void>((resolve) => {
      this.socket.end(() => resolve());
    });
  }
}

describe('Live Distributed Shield Stores (PostgreSQL 16 & Redis 7)', () => {
  it(
    'PostgresShieldStorage enforces distributed locks, idempotency cache, and sliding-window loop breaker against live PostgreSQL',
    { skip: !process.env.POSTGRES_URL },
    async () => {
      const pool = new Pool({ connectionString: process.env.POSTGRES_URL });
      const store = new PostgresShieldStorage(pool, { vacuumIntervalCalls: 10 });
      try {
        await store.clear();

        // 1. Distributed mutual-exclusion lock verification
        const lockKey = `live-pg-lock-${Date.now()}`;
        const firstAcquire = await store.acquireLock(lockKey, 15_000);
        const secondAcquire = await store.acquireLock(lockKey, 15_000);
        assert.equal(firstAcquire, true, 'First worker must acquire PostgreSQL lock');
        assert.equal(secondAcquire, false, 'Concurrent worker must be blocked while lock is unexpired');

        await store.releaseLock(lockKey);
        const reAcquire = await store.acquireLock(lockKey, 15_000);
        assert.equal(reAcquire, true, 'Lock must be acquirable after releaseLock()');
        await store.releaseLock(lockKey);

        // 2. End-to-end ShieldMiddleware idempotency & loop breaker over live PostgreSQL
        const shield = new ShieldMiddleware({
          storage: store,
          idempotency: true,
          loopLimit: { count: 2, windowMs: 30_000 },
        });

        let executions = 0;
        const handler = async (req: { method: string; params: { name: string; arguments?: Record<string, any> } }) => {
          executions++;
          return {
            content: [{ type: 'text' as const, text: `charged:${req.params.arguments?.amount}` }],
          };
        };

        const firstCall = await shield.intercept(
          { method: 'tools/call', params: { name: 'charge_customer', arguments: { amount: 4999, idempotencyKey: 'idem_pg_001' } } },
          handler
        );
        const duplicateCall = await shield.intercept(
          { method: 'tools/call', params: { name: 'charge_customer', arguments: { amount: 4999, idempotencyKey: 'idem_pg_001' } } },
          handler
        );
        assert.equal(executions, 1, 'Duplicate idempotencyKey must hit PostgreSQL cache without re-executing');
        assert.equal(duplicateCall.content[0]?.text, firstCall.content[0]?.text);
        assert.equal(duplicateCall._shield?.cached, true);

        // Trigger loop breaker on repeated identical read calls (count: 2)
        await shield.intercept({ method: 'tools/call', params: { name: 'get_ledger_balance', arguments: { accountId: 'acct_live' } } }, handler);
        await shield.intercept({ method: 'tools/call', params: { name: 'get_ledger_balance', arguments: { accountId: 'acct_live' } } }, handler);
        const thirdCall = await shield.intercept(
          { method: 'tools/call', params: { name: 'get_ledger_balance', arguments: { accountId: 'acct_live' } } },
          handler
        );
        assert.equal(thirdCall.isError, true);
        assert.ok(thirdCall.content[0]?.text.includes('Loop detected'));
      } finally {
        await pool.end();
      }
    }
  );

  it(
    'RedisShieldStorage enforces atomic Lua locks, idempotency cache, and ZSET loop breaker against live Redis',
    { skip: !process.env.REDIS_URL },
    async () => {
      const redis = await Resp2RedisClient.connect(process.env.REDIS_URL!);
      const store = new RedisShieldStorage(redis, { mode: 'strict' });
      const runTag = `live-redis-${Date.now()}`;
      try {
        // 1. Atomic Lua SET PX NX lock contention in strict mode (-32001)
        const lockKey = `${runTag}:lock`;
        const acquired = await store.acquireLock(lockKey, 15_000);
        assert.equal(acquired, true);
        await assert.rejects(
          () => store.acquireLock(lockKey, 15_000),
          (err: any) => err?.code === -32001
        );
        await store.releaseLock(lockKey);

        // 2. End-to-end ShieldMiddleware idempotency & Lua ZSET loop breaker over live Redis
        const shield = new ShieldMiddleware({
          storage: store,
          idempotency: true,
          loopLimit: { count: 2, windowMs: 30_000 },
        });

        let wireExecutions = 0;
        const handler = async () => {
          wireExecutions++;
          return { content: [{ type: 'text' as const, text: 'wire_sent_ok' }] };
        };

        const firstWire = await shield.intercept(
          { method: 'tools/call', params: { name: 'send_wire', arguments: { wireId: `${runTag}:w1`, idempotencyKey: `${runTag}:idem1` } } },
          handler
        );
        const dupWire = await shield.intercept(
          { method: 'tools/call', params: { name: 'send_wire', arguments: { wireId: `${runTag}:w1`, idempotencyKey: `${runTag}:idem1` } } },
          handler
        );
        assert.equal(wireExecutions, 1, 'Duplicate idempotencyKey must hit Redis cache without re-executing');
        assert.equal(dupWire.content[0]?.text, firstWire.content[0]?.text);
        assert.equal(dupWire._shield?.cached, true);

        await shield.intercept({ method: 'tools/call', params: { name: 'poll_wire_status', arguments: { wireId: runTag } } }, handler);
        await shield.intercept({ method: 'tools/call', params: { name: 'poll_wire_status', arguments: { wireId: runTag } } }, handler);
        const thirdWire = await shield.intercept(
          { method: 'tools/call', params: { name: 'poll_wire_status', arguments: { wireId: runTag } } },
          handler
        );
        assert.equal(thirdWire.isError, true);
        assert.ok(thirdWire.content[0]?.text.includes('Loop detected'));
      } finally {
        await redis.close();
      }
    }
  );
});
