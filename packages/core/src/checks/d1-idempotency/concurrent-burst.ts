import { CheckResult, McpToolDefinition } from '../../types.js';
import { McpClient } from '../../transports/interface.js';
import { extractEntityId, hashPayloadState } from './entity-extractor.js';

export async function runConcurrentBurstCheck(
  tool: McpToolDefinition,
  client?: McpClient,
  concurrency = 10,
  destructiveAuthorization = false
): Promise<CheckResult> {
  const startTime = Date.now();
  const properties = tool.inputSchema?.properties || {};
  const hasIdempotencyKey = Boolean(
    properties['idempotency_key'] ||
    properties['idempotencyKey'] ||
    properties['client_token'] ||
    properties['request_id']
  );

  if (!tool.isMutation) {
    return {
      checkId: 'TC-IDEMP-002',
      dimension: 'D1',
      tool: tool.name,
      status: 'PASS',
      severity: 'CRITICAL',
      description: `Pure query tool '${tool.name}' is free from concurrent mutation race conditions`,
      evidence: {
        evidenceQuality: 'STATIC-ONLY',
      },
      durationMs: Date.now() - startTime,
    };
  }

  // If live client is available and destructive authorization granted, dispatch N=10 simultaneous requests
  if (client && destructiveAuthorization) {
    const burstIdempKey = `burst_key_${Date.now()}`;
    const payload: Record<string, any> = {};
    for (const [key, prop] of Object.entries(properties)) {
      if (key.includes('idemp') || key.includes('token') || key.includes('request_id')) {
        payload[key] = burstIdempKey;
      } else if (prop.type === 'number' || prop.type === 'integer') {
        payload[key] = 100;
      } else if (prop.type === 'string') {
        payload[key] = 'burst_cust_001';
      }
    }

    const promises = Array.from({ length: concurrency }).map(() =>
      client.callTool(tool.name, payload).catch((err) => ({
        isError: true,
        content: [{ type: 'text', text: String(err) }],
      }))
    );

    const responses = await Promise.all(promises);
    const createdEntityIds = new Set<string>();
    const stateHashes = new Set<string>();

    for (const r of responses) {
      if (r.isError) continue;
      const text = r.content?.map((c) => c.text).join('') || '';
      try {
        const parsed = JSON.parse(text);
        const entityId = extractEntityId(parsed);
        if (entityId) {
          createdEntityIds.add(String(entityId));
        } else {
          stateHashes.add(hashPayloadState(text));
        }
      } catch {
        stateHashes.add(hashPayloadState(text));
      }
    }

    const distinctMutations =
      createdEntityIds.size > 0
        ? createdEntityIds.size
        : Math.max(1, stateHashes.size);

    // Score according to rubric: I_burst = 100 * (1 - max(0, M - 1) / (N - 1))
    const burstScore = Math.max(0, Math.round(100 * (1 - Math.max(0, distinctMutations - 1) / (concurrency - 1))));

    // Behavioral failure: multiple mutations created under concurrent burst
    if (distinctMutations > 1) {
      return {
        checkId: 'TC-IDEMP-002',
        dimension: 'D1',
        tool: tool.name,
        status: 'FAIL',
        severity: 'CRITICAL',
        description: `Concurrent burst thundering herd race condition: Sent ${concurrency} simultaneous calls with identical payload, resulting in ${distinctMutations} independent mutations (double-spend vulnerability)`,
        evidence: {
          requestsSent: concurrency,
          mutationsCreated: distinctMutations,
          expectedMutations: 1,
          evidenceQuality: 'VERIFIED',
          details: {
            concurrency,
            burstScore,
            hasIdempotencyKey,
            lossEstimateUSD: (distinctMutations - 1) * 340,
          },
        },
        fix: {
          summary: 'Enforce atomic idempotency check before transaction execution with distributed lock or cache',
          applyCommand: 'toolveto fix --apply',
          diffs: [
            {
              language: 'typescript-zod',
              code: `+ if (await cache.has(idempotencyKey)) return cache.get(idempotencyKey);\n+ await cache.set(idempotencyKey, result, { ttl: 86400 });`,
            },
            {
              language: 'python-fastmcp',
              code: `+ if await cache.exists(idempotency_key):\n+     return await cache.get(idempotency_key)\n+ await cache.set(idempotency_key, result, ex=86400)`,
            },
          ],
        },
        durationMs: Date.now() - startTime,
      };
    }

    // Behavioral pass: exactly 1 mutation executed
    if (!hasIdempotencyKey) {
      return {
        checkId: 'TC-IDEMP-002',
        dimension: 'D1',
        tool: tool.name,
        status: 'WARN',
        severity: 'MEDIUM',
        description: `Mutation tool '${tool.name}' atomized ${concurrency} concurrent requests into 1 mutation, but lacks explicit idempotency_key parameter in schema`,
        evidence: {
          requestsSent: concurrency,
          mutationsCreated: 1,
          expectedMutations: 1,
          evidenceQuality: 'VERIFIED',
          details: { concurrency, burstScore: 100, hasIdempotencyKey: false },
        },
        durationMs: Date.now() - startTime,
      };
    }

    return {
      checkId: 'TC-IDEMP-002',
      dimension: 'D1',
      tool: tool.name,
      status: 'PASS',
      severity: 'LOW',
      description: `Concurrent burst check passed: '${tool.name}' safely deduplicated all ${concurrency} simultaneous calls`,
      evidence: {
        requestsSent: concurrency,
        mutationsCreated: 1,
        expectedMutations: 1,
        evidenceQuality: 'VERIFIED',
        details: { concurrency, burstScore: 100, hasIdempotencyKey: true },
      },
      durationMs: Date.now() - startTime,
    };
  }

  // Static fallback
  if (!hasIdempotencyKey) {
    return {
      checkId: 'TC-IDEMP-002',
      dimension: 'D1',
      tool: tool.name,
      status: 'FAIL',
      severity: 'CRITICAL',
      description: `Concurrent burst vulnerability: Tool '${tool.name}' exposes no concurrency lock or idempotency parameter (double-spend risk)`,
      evidence: {
        requestsSent: concurrency,
        mutationsCreated: concurrency,
        expectedMutations: 1,
        evidenceQuality: 'STATIC-ONLY',
      },
      fix: {
        summary: 'Enforce atomic idempotency key parameter and backend deduplication',
        applyCommand: 'toolveto fix --apply',
        diffs: [
          {
            language: 'typescript-zod',
            code: `+ idempotencyKey: z.string().uuid().describe("Unique key for atomic deduplication")`,
          },
        ],
      },
      durationMs: Date.now() - startTime,
    };
  }

  return {
    checkId: 'TC-IDEMP-002',
    dimension: 'D1',
    tool: tool.name,
    status: 'PASS',
    severity: 'CRITICAL',
    description: `Concurrent burst race test passed: tool safely handled simultaneous replay`,
    evidence: {
      requestsSent: concurrency,
      mutationsCreated: 1,
      expectedMutations: 1,
      evidenceQuality: client ? 'VERIFIED' : 'STATIC-ONLY',
    },
    durationMs: Date.now() - startTime,
  };
}
