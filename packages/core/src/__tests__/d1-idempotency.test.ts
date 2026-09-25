import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { runSequentialReplayCheck } from '../checks/d1-idempotency/sequential-replay.js';
import { runConcurrentBurstCheck } from '../checks/d1-idempotency/concurrent-burst.js';
import { runIdempotencyKeyCheck } from '../checks/d1-idempotency/idempotency-key.js';
import { InMemoryMcpClient } from '../transports/in-memory.js';
import { McpToolDefinition } from '../types.js';

describe('D1: Idempotency & Concurrency Battery', () => {
  it('TC-IDEMP-001: should flag mutation tool without idempotency key as CRITICAL failure with diff', async () => {
    const badTool: McpToolDefinition = {
      name: 'charge_wallet',
      description: 'Charges user balance without key',
      isMutation: true,
      inputSchema: {
        type: 'object',
        properties: { amount: { type: 'number' } },
        required: ['amount'],
      },
    };

    const result = await runSequentialReplayCheck(badTool);
    assert.strictEqual(result.checkId, 'TC-IDEMP-001');
    assert.strictEqual(result.status, 'FAIL');
    assert.strictEqual(result.severity, 'CRITICAL');
    assert.ok(result.fix);
    assert.ok(result.fix.diffs.some((d) => d.language === 'typescript-zod'));
  });

  it('TC-IDEMP-001: should pass mutation tool with valid idempotency_key parameter', async () => {
    const goodTool: McpToolDefinition = {
      name: 'charge_wallet',
      description: 'Charges user balance safely with idempotency',
      isMutation: true,
      inputSchema: {
        type: 'object',
        properties: {
          amount: { type: 'number' },
          idempotency_key: { type: 'string' },
        },
        required: ['amount', 'idempotency_key'],
      },
    };

    const result = await runSequentialReplayCheck(goodTool);
    assert.strictEqual(result.status, 'PASS');
  });

  it('TC-IDEMP-002: should detect live double-spend race condition during concurrent burst', async () => {
    let mutationsCreated = 0;
    const badTool: McpToolDefinition = {
      name: 'create_order',
      description: 'Creates purchase order without lock',
      isMutation: true,
      inputSchema: {
        type: 'object',
        properties: { item_id: { type: 'string' } },
      },
    };

    const client = new InMemoryMcpClient([
      {
        definition: badTool,
        handler: async () => {
          mutationsCreated++;
          return {
            content: [{ type: 'text', text: `Order created #${mutationsCreated}` }],
          };
        },
      },
    ]);

    const result = await runConcurrentBurstCheck(badTool, client, 10);
    assert.strictEqual(result.checkId, 'TC-IDEMP-002');
    assert.strictEqual(result.status, 'FAIL');
    assert.strictEqual(result.severity, 'CRITICAL');
    assert.ok(result.description.includes('double-spend'));
  });

  it('TC-IDEMP-002: should pass concurrent burst when server atomically deduplicates calls', async () => {
    const goodTool: McpToolDefinition = {
      name: 'create_order',
      description: 'Creates purchase order with atomic deduplication',
      isMutation: true,
      inputSchema: {
        type: 'object',
        properties: {
          item_id: { type: 'string' },
          idempotency_key: { type: 'string' },
        },
      },
    };

    const cache = new Map<string, any>();
    const client = new InMemoryMcpClient([
      {
        definition: goodTool,
        handler: async (args) => {
          const key = args.idempotency_key;
          if (cache.has(key)) {
            return cache.get(key);
          }
          const resp = { content: [{ type: 'text', text: 'Order created #1' }] };
          cache.set(key, resp);
          return resp;
        },
      },
    ]);

    const result = await runConcurrentBurstCheck(goodTool, client, 10);
    assert.strictEqual(result.status, 'PASS');
    assert.strictEqual(result.evidence.mutationsCreated, 1);
  });

  it('TC-IDEMP-003: evaluates schema idempotency key presence', () => {
    const toolWithKey: McpToolDefinition = {
      name: 'pay',
      isMutation: true,
      inputSchema: { type: 'object', properties: { client_request_id: { type: 'string' } } },
    };
    const res = runIdempotencyKeyCheck(toolWithKey);
    assert.strictEqual(res.status, 'PASS');

    const toolWithoutKey: McpToolDefinition = {
      name: 'pay',
      isMutation: true,
      inputSchema: { type: 'object', properties: { amount: { type: 'number' } } },
    };
    const failRes = runIdempotencyKeyCheck(toolWithoutKey);
    assert.strictEqual(failRes.status, 'FAIL');
  });
});
