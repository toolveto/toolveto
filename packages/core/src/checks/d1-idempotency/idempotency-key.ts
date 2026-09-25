import { CheckResult, McpToolDefinition } from '../../types.js';

export function runIdempotencyKeyCheck(tool: McpToolDefinition): CheckResult {
  const startTime = Date.now();
  if (!tool.isMutation) {
    return {
      checkId: 'TC-IDEMP-003',
      dimension: 'D1',
      tool: tool.name,
      status: 'PASS',
      severity: 'LOW',
      description: `Query tool '${tool.name}' is read-only and does not require explicit idempotency key`,
      evidence: { evidenceQuality: 'STATIC-ONLY' },
      durationMs: Date.now() - startTime,
    };
  }

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
      description: `Schema declares explicit idempotency key on '${tool.name}'`,
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
    description: `Missing explicit idempotency key in schema definition for mutation tool '${tool.name}'`,
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
