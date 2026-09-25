import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { ShieldMiddleware, shield } from '../index.js';

describe('ToolVeto Shield Runtime Middleware', () => {
  it('should intercept and block infinite retry loops (loopLimit)', async () => {
    const middleware = new ShieldMiddleware({
      loopLimit: { count: 3, windowMs: 5000 },
    });

    let callsHandled = 0;
    const mockNext = async () => {
      callsHandled++;
      return { content: [{ type: 'text', text: 'ok' }] };
    };

    const req = {
      method: 'tools/call',
      params: { name: 'failing_tool', arguments: {} },
    };

    // 1st call
    const res1 = await middleware.intercept(req, mockNext);
    assert.strictEqual(res1.isError, undefined);

    // 2nd call
    const res2 = await middleware.intercept(req, mockNext);
    assert.strictEqual(res2.isError, undefined);

    // 3rd call
    const res3 = await middleware.intercept(req, mockNext);
    assert.strictEqual(res3.isError, undefined);

    // 4th call — exceeds count 3 within window, must halt!
    const res4 = await middleware.intercept(req, mockNext);
    assert.strictEqual(res4.isError, true);
    assert.ok(res4.content[0].text.includes('Loop detected'));
    assert.strictEqual(callsHandled, 3, 'Backend handler should NOT be called after loop breaker triggers');
  });

  it('should deduplicate mutations via idempotency_key caching', async () => {
    const middleware = new ShieldMiddleware({ idempotency: true });
    let backendMutations = 0;

    const mockNext = async (r: any) => {
      backendMutations++;
      return {
        content: [{ type: 'text', text: `Charged receipt #${backendMutations}` }],
      };
    };

    const req = {
      method: 'tools/call',
      params: {
        name: 'charge_card',
        arguments: { amount: 50, idempotency_key: 'idemp_uuid_123' },
      },
    };

    // 1st call: executes backend mutation
    const res1 = await middleware.intercept(req, mockNext);
    assert.strictEqual(res1.content[0].text, 'Charged receipt #1');
    assert.strictEqual(backendMutations, 1);

    // 2nd call with identical key: returns cached receipt without executing backend!
    const res2 = await middleware.intercept(req, mockNext);
    assert.strictEqual(res2.content[0].text, 'Charged receipt #1');
    assert.strictEqual(backendMutations, 1, 'Duplicate mutation must NOT hit backend');

    // Call with different key: executes new mutation
    const req2 = {
      method: 'tools/call',
      params: {
        name: 'charge_card',
        arguments: { amount: 50, idempotency_key: 'idemp_uuid_456' },
      },
    };
    const res3 = await middleware.intercept(req2, mockNext);
    assert.strictEqual(res3.content[0].text, 'Charged receipt #2');
    assert.strictEqual(backendMutations, 2);
  });

  it('should truncate responses exceeding token budget to prevent context bombs', async () => {
    const middleware = new ShieldMiddleware({ tokenBudget: 100 }); // 100 tokens ~= 400 chars

    const mockNext = async () => ({
      content: [{ type: 'text', text: 'Z'.repeat(1000) }],
    });

    const req = {
      method: 'tools/call',
      params: { name: 'list_logs', arguments: {} },
    };

    const res = await middleware.intercept(req, mockNext);
    assert.ok(res.content[0].text.length < 600);
    assert.ok(res.content[0].text.includes('Truncated to prevent context exhaustion'));
  });

  it('should proxy server handleCallTool cleanly via shield() function', async () => {
    class MockServer {
      public callCount = 0;
      async handleCallTool(req: any) {
        this.callCount++;
        return { content: [{ type: 'text', text: `call ${this.callCount}` }] };
      }
    }

    const rawServer = new MockServer();
    const shielded = shield(rawServer, {
      loopLimit: { count: 2, windowMs: 10000 },
    });

    const req = { method: 'tools/call', params: { name: 'test_tool' } };
    await (shielded as any).handleCallTool(req);
    await (shielded as any).handleCallTool(req);
    const blocked = await (shielded as any).handleCallTool(req);

    assert.strictEqual(blocked.isError, true);
    assert.ok(blocked.content[0].text.includes('Loop detected'));
    assert.strictEqual(rawServer.callCount, 2);
  });

  it('should track metrics for intercepted calls and deduplications', async () => {
    const middleware = new ShieldMiddleware({ idempotency: true });
    const mockNext = async () => ({
      content: [{ type: 'text', text: 'response' }],
    });

    const req = {
      method: 'tools/call',
      params: { name: 'transfer', arguments: { idempotency_key: 'tx_123' } },
    };

    await middleware.intercept(req, mockNext);
    await middleware.intercept(req, mockNext);

    const metrics = middleware.getMetrics();
    assert.strictEqual(metrics.totalCalls, 2);
    assert.strictEqual(metrics.deduplicatedCalls, 1);
  });

  it('should allow repeating calls if arguments differ, but block on identical arguments', async () => {
    const middleware = new ShieldMiddleware({
      loopLimit: { count: 2, windowMs: 5000 },
    });

    const mockNext = async () => ({
      content: [{ type: 'text', text: 'ok' }],
    });

    // 2 calls with different arguments: allowed
    const res1 = await middleware.intercept(
      { method: 'tools/call', params: { name: 'search', arguments: { q: 'cats' } } },
      mockNext
    );
    const res2 = await middleware.intercept(
      { method: 'tools/call', params: { name: 'search', arguments: { q: 'dogs' } } },
      mockNext
    );
    assert.strictEqual(res1.isError, undefined);
    assert.strictEqual(res2.isError, undefined);

    // 3 calls with identical arguments: triggers loop breaker on 3rd call
    const callIdentical = () =>
      middleware.intercept(
        { method: 'tools/call', params: { name: 'search', arguments: { q: 'infinite' } } },
        mockNext
      );

    await callIdentical();
    await callIdentical();
    const blocked = await callIdentical();

    assert.strictEqual(blocked.isError, true);
    assert.ok(blocked.content[0].text.includes('Loop detected'));
  });

  it('should support RedisShieldStorage adapter with sorted set sliding window', async () => {
    const memoryRedis: Record<string, string> = {};
    const zsetRecords: Record<string, Array<{ score: number; member: string }>> = {};

    const mockRedisClient = {
      async get(key: string) {
        return memoryRedis[key] || null;
      },
      async set(key: string, value: string) {
        memoryRedis[key] = value;
        return 'OK';
      },
      async zremrangebyscore(key: string, min: string | number, max: string | number) {
        const threshold = Number(max);
        zsetRecords[key] = (zsetRecords[key] || []).filter((item) => item.score > threshold);
        return 0;
      },
      async zadd(key: string, score: number, member: string) {
        if (!zsetRecords[key]) zsetRecords[key] = [];
        zsetRecords[key].push({ score, member });
        return 1;
      },
      async zcard(key: string) {
        return (zsetRecords[key] || []).length;
      },
      async expire() {
        return 1;
      },
    };

    const redisStorage = new (await import('../stores/redis.js')).RedisShieldStorage(mockRedisClient);
    const middleware = new ShieldMiddleware({
      storage: redisStorage,
      loopLimit: { count: 2, windowMs: 5000 },
      idempotency: true,
    });

    let backendCalls = 0;
    const mockNext = async () => {
      backendCalls++;
      return { content: [{ type: 'text', text: 'result' }] };
    };

    // 1st call with idempotency_key
    const req1 = {
      method: 'tools/call',
      params: { name: 'pay', arguments: { amount: 100, idempotency_key: 'redis_key_1' } },
    };
    await middleware.intercept(req1, mockNext);
    assert.strictEqual(backendCalls, 1);

    // 2nd call: cached from Redis
    const res2 = await middleware.intercept(req1, mockNext);
    assert.strictEqual(res2._shield?.cached, true);
    assert.strictEqual(backendCalls, 1);

    // 3rd call triggers loop breaker
    const blocked = await middleware.intercept(req1, mockNext);
    assert.strictEqual(blocked.isError, true);
    assert.ok(blocked.content[0].text.includes('Loop detected'));
  });
});

