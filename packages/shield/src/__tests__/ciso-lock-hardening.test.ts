import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ShieldMiddleware } from '../index.js';
import { RedisShieldStorage } from '../stores/redis.js';
import { PostgresShieldStorage } from '../stores/postgres.js';

describe('CISO PATCH-16: Distributed Lock Owner-Token Safety & Bounded Lock TTL', () => {
  it('RedisShieldStorage: non-owner instance cannot delete active lock held by another worker', async () => {
    const store = new Map<string, string>();
    const fakeRedis = {
      async get(key: string) {
        return store.get(key) ?? null;
      },
      async set(key: string, value: string, _mode?: string, _dur?: number, flag?: string) {
        if (flag === 'NX' && store.has(key)) return null;
        store.set(key, value);
        return 'OK';
      },
      async del(key: string) {
        return store.delete(key) ? 1 : 0;
      },
      async eval(script: string, _numkeys: number, ...args: (string | number)[]) {
        const key = String(args[0]);
        if (script.includes("redis.call('SET'")) {
          if (store.has(key)) return 0;
          store.set(key, String(args[2]));
          return 1;
        }
        if (script.includes("redis.call('GET'")) {
          if (store.get(key) === String(args[1])) {
            store.delete(key);
            return 1;
          }
          return 0;
        }
        return 0;
      },
    };

    const workerA = new RedisShieldStorage(fakeRedis, { mode: 'standard' });
    const workerB = new RedisShieldStorage(fakeRedis, { mode: 'standard' });

    assert.equal(await workerA.acquireLock('op-key-1', 5000), true);
    assert.equal(await workerB.acquireLock('op-key-1', 5000), false);

    // Worker B calling releaseLock MUST NOT delete Worker A's lock
    await workerB.releaseLock('op-key-1');
    assert.ok(store.has('shield:lock:op-key-1'), 'Worker B must not delete lock owned by Worker A');

    // Simulate Worker A's lock expiring and Worker B acquiring a fresh lock with a new token
    store.delete('shield:lock:op-key-1');
    assert.equal(await workerB.acquireLock('op-key-1', 5000), true);
    const workerBToken = store.get('shield:lock:op-key-1');

    // Delayed release from Worker A MUST NOT delete Worker B's lock!
    await workerA.releaseLock('op-key-1');
    assert.equal(store.get('shield:lock:op-key-1'), workerBToken, 'Delayed Worker A release must not delete Worker B lock');

    // Worker B releasing its own lock succeeds
    await workerB.releaseLock('op-key-1');
    assert.equal(store.has('shield:lock:op-key-1'), false);
  });

  it('PostgresShieldStorage: releaseLock deletes only when owner_token matches', async () => {
    const lockTable = new Map<string, { expires_at: number; owner_token: string }>();
    const fakePg = {
      async query(sql: string, params: any[] = []) {
        if (sql.includes('CREATE TABLE') || sql.includes('ALTER TABLE')) {
          return { rows: [] };
        }
        if (sql.includes('INSERT INTO toolveto_shield_locks')) {
          const [key, expiresAt, ownerToken, now] = params;
          const existing = lockTable.get(key);
          if (!existing || existing.expires_at < now) {
            lockTable.set(key, { expires_at: expiresAt, owner_token: ownerToken });
            return { rows: [{ key }] };
          }
          return { rows: [] };
        }
        if (sql.includes('DELETE FROM toolveto_shield_locks WHERE key = $1 AND owner_token = $2')) {
          const [key, ownerToken] = params;
          const existing = lockTable.get(key);
          if (existing && existing.owner_token === ownerToken) {
            lockTable.delete(key);
          }
          return { rows: [] };
        }
        return { rows: [] };
      },
    };

    const pgA = new PostgresShieldStorage(fakePg);
    const pgB = new PostgresShieldStorage(fakePg);

    assert.equal(await pgA.acquireLock('pg-lock-1', 5000), true);
    assert.equal(await pgB.acquireLock('pg-lock-1', 5000), false);

    await pgB.releaseLock('pg-lock-1');
    assert.ok(lockTable.has('pg-lock-1'), 'Non-owner pgB must not delete pgA lock');

    // Simulate lock expiration and takeover by pgB
    lockTable.set('pg-lock-1', { expires_at: Date.now() - 10, owner_token: 'expired' });
    assert.equal(await pgB.acquireLock('pg-lock-1', 5000), true);
    const bOwner = lockTable.get('pg-lock-1')?.owner_token;

    await pgA.releaseLock('pg-lock-1');
    assert.equal(lockTable.get('pg-lock-1')?.owner_token, bOwner, 'Stale pgA release must not delete pgB lock');

    await pgB.releaseLock('pg-lock-1');
    assert.equal(lockTable.has('pg-lock-1'), false);
  });

  it('ShieldMiddleware caps execution lock TTL to <= 30,000ms even when idempotencyTtlMs is 24h', async () => {
    const acquiredTtls: number[] = [];
    const customStorage = {
      async get() {
        return undefined;
      },
      async set() {},
      async recordCall() {
        return 1;
      },
      async acquireLock(_key: string, ttlMs?: number) {
        acquiredTtls.push(ttlMs ?? 0);
        return true;
      },
      async releaseLock() {},
    };

    const mw = new ShieldMiddleware({
      idempotency: true,
      idempotencyTtlMs: 86_400_000, // 24 hours
      storage: customStorage,
    });
    const res = await mw.intercept(
      { method: 'tools/call', params: { name: 'create_payment', arguments: { idempotency_key: 'idem_123', amount: 10 } } },
      async () => ({ content: [{ type: 'text', text: 'ok' }] })
    );
    assert.equal(res.isError, undefined);
    assert.equal(acquiredTtls.length, 1);
    assert.ok(acquiredTtls[0] <= 30_000 && acquiredTtls[0] >= 1000, `Expected lock TTL <= 30000ms, got ${acquiredTtls[0]}`);
  });
});
