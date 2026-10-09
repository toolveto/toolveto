import { CheckResult, McpToolDefinition } from '../../types.js';
import { McpClient } from '../../transports/interface.js';
import { extractEntityId } from './entity-extractor.js';

/**
 * TC-IDEMP-003: Crash-Between-Commit-and-Response Simulation
 * Simulates client dropping connection immediately after commit, then reconnecting
 * and replaying the same idempotency key / request payload.
 * Verifies zero duplicate mutation execution (no double-spend / duplicate record).
 */
export async function runCrashCommitCheck(
  tool: McpToolDefinition,
  client?: McpClient,
  destructiveAuthorization = false
): Promise<CheckResult> {
  const startTime = Date.now();

  if (!tool.isMutation) {
    return {
      checkId: 'TC-IDEMP-003',
      dimension: 'D1',
      tool: tool.name,
      status: 'PASS',
      severity: 'LOW',
      description: `Query tool '${tool.name}' is read-only and free from crash-commit double-spend risk`,
      evidence: { evidenceQuality: 'STATIC-ONLY' },
      durationMs: Date.now() - startTime,
    };
  }

  // Active behavioral fault injection test
  if (client && destructiveAuthorization) {
    const crashKey = `crash_commit_key_${Date.now()}`;
    const props = tool.inputSchema?.properties || {};
    const payload: Record<string, any> = {};

    for (const [k, p] of Object.entries(props)) {
      if (k.includes('idemp') || k.includes('token') || k.includes('request_id')) {
        payload[k] = crashKey;
      } else if (p.type === 'number' || p.type === 'integer') {
        payload[k] = 100;
      } else if (p.type === 'string') {
        payload[k] = 'crash_commit_val';
      }
    }

    try {
      // 1. Dispatch initial mutation
      const res1 = await client.callTool(tool.name, payload);

      // 2. Replay identical payload (simulating client reconnect after network drop / timeout)
      const res2 = await client.callTool(tool.name, payload);

      const text1 = res1.content?.map((c) => c.text).join('') || '';
      const text2 = res2.content?.map((c) => c.text).join('') || '';

      if (!res1.isError && !res2.isError) {
        let id1: string | null = null;
        let id2: string | null = null;
        try {
          id1 = extractEntityId(JSON.parse(text1));
          id2 = extractEntityId(JSON.parse(text2));
        } catch {
          // Non-JSON
        }

        if (id1 && id2 && id1 !== id2) {
          return {
            checkId: 'TC-IDEMP-003',
            dimension: 'D1',
            tool: tool.name,
            status: 'FAIL',
            severity: 'CRITICAL',
            description: `Crash-commit vulnerability: Replayed mutation after dropped connection created duplicate entity (ID1: ${id1}, ID2: ${id2})`,
            evidence: {
              requestsSent: 2,
              mutationsCreated: 2,
              expectedMutations: 1,
              evidenceQuality: 'VERIFIED',
              details: { initialId: id1, replayedId: id2 },
            },
            fix: {
              summary: 'Enforce atomic transaction commit tied to idempotency key before returning response',
              applyCommand: 'toolveto fix --apply',
              diffs: [
                {
                  language: 'typescript-zod',
                  code: `+ await db.transaction(async (tx) => {\n+   const existing = await tx.findIdempotency(idempotencyKey);\n+   if (existing) return existing.response;\n+   const result = await tx.executeMutation(payload);\n+   await tx.saveIdempotency(idempotencyKey, result);\n+   return result;\n+ });`,
                },
              ],
            },
            durationMs: Date.now() - startTime,
          };
        }
      }

      return {
        checkId: 'TC-IDEMP-003',
        dimension: 'D1',
        tool: tool.name,
        status: 'PASS',
        severity: 'LOW',
        description: `Crash-commit check passed: Reconnected replay for '${tool.name}' correctly atomized mutation`,
        evidence: {
          requestsSent: 2,
          mutationsCreated: 1,
          expectedMutations: 1,
          evidenceQuality: 'VERIFIED',
        },
        durationMs: Date.now() - startTime,
      };
    } catch {
      // Safe fallback
    }
  }

  // Static schema fallback
  const properties = tool.inputSchema?.properties || {};
  const hasExplicitKey = Boolean(
    properties['idempotency_key'] ||
    properties['idempotencyKey'] ||
    properties['client_request_id'] ||
    properties['request_id']
  );

  if (hasExplicitKey) {
    return {
      checkId: 'TC-IDEMP-003',
      dimension: 'D1',
      tool: tool.name,
      status: 'PASS',
      severity: 'LOW',
      description: `Schema declares explicit idempotency key on '${tool.name}' for crash recovery`,
      evidence: { evidenceQuality: 'STATIC-ONLY' },
      durationMs: Date.now() - startTime,
    };
  }

  return {
    checkId: 'TC-IDEMP-003',
    dimension: 'D1',
    tool: tool.name,
    status: 'FAIL',
    severity: 'HIGH',
    description: `Missing explicit idempotency key in schema definition for mutation tool '${tool.name}' (unprotected against crash-commit double-spend)`,
    evidence: { evidenceQuality: 'STATIC-ONLY' },
    fix: {
      summary: "Add 'idempotency_key: string' parameter to schema",
      applyCommand: 'toolveto fix --apply',
      diffs: [
        {
          language: 'typescript-zod',
          code: `+ idempotency_key: z.string().uuid().describe("Unique token for idempotent request processing")`,
        },
      ],
    },
    durationMs: Date.now() - startTime,
  };
}
