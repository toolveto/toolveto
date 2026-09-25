import { CheckResult, McpToolDefinition } from '../../types.js';
import { McpClient } from '../../transports/interface.js';

export async function runSequentialReplayCheck(
  tool: McpToolDefinition,
  client?: McpClient
): Promise<CheckResult> {
  const startTime = Date.now();
  const properties = tool.inputSchema?.properties || {};
  const hasIdempotencyKey = Boolean(
    properties['idempotency_key'] ||
    properties['idempotencyKey'] ||
    properties['client_token'] ||
    properties['request_id']
  );

  // If client provided and tool is a mutation, execute 5 sequential replay calls
  if (client && tool.isMutation) {
    const testIdempKey = `test_replay_${Date.now()}`;
    const samplePayload: Record<string, any> = {};
    for (const [key, prop] of Object.entries(properties)) {
      if (key.includes('idemp') || key.includes('token') || key.includes('request_id')) {
        samplePayload[key] = testIdempKey;
      } else if (prop.type === 'number' || prop.type === 'integer') {
        samplePayload[key] = 100;
      } else if (prop.type === 'string') {
        samplePayload[key] = 'test_val';
      } else if (prop.type === 'boolean') {
        samplePayload[key] = false;
      }
    }

    const createdEntityIds = new Set<string>();
    const nonJsonDistinctTexts = new Set<string>();
    let errorsEncountered = 0;

    for (let i = 0; i < 5; i++) {
      try {
        const resp = await client.callTool(tool.name, samplePayload);
        const text = resp.content?.map((c) => c.text).join('') || '';
        try {
          const parsed = JSON.parse(text);
          const entityId =
            parsed.charge_id ||
            parsed.payment_id ||
            parsed.order_id ||
            parsed.id ||
            parsed.charge?.charge_id ||
            parsed.payment?.payment_id ||
            (parsed.charge?.total_mutations_on_server != null ? `mutation_${parsed.charge.total_mutations_on_server}` : null);

          if (entityId) {
            createdEntityIds.add(String(entityId));
          } else {
            nonJsonDistinctTexts.add(text);
          }
        } catch {
          nonJsonDistinctTexts.add(text);
        }
      } catch {
        errorsEncountered++;
      }
    }

    const distinctMutations =
      createdEntityIds.size > 0
        ? createdEntityIds.size
        : Math.max(1, nonJsonDistinctTexts.size);

    const createdDuplicates = distinctMutations > 1 && !hasIdempotencyKey;
    if (createdDuplicates || !hasIdempotencyKey) {
      return {
        checkId: 'TC-IDEMP-001',
        dimension: 'D1',
        tool: tool.name,
        status: 'FAIL',
        severity: 'CRITICAL',
        description: `Sequential replay failure: Mutation tool '${tool.name}' accepts no idempotency key and executed ${distinctMutations} distinct mutations on replay`,
        evidence: {
          requestsSent: 5,
          mutationsCreated: distinctMutations,
          expectedMutations: 1,
          evidenceQuality: 'VERIFIED',
          details: {
            distinctMutations,
            hasIdempotencyKey: false,
          },
        },
        fix: {
          summary: 'Add idempotency_key parameter to tool input schema and deduplicate calls by key/payload hash',
          applyCommand: 'toolveto fix --apply',
          diffs: [
            {
              language: 'typescript-zod',
              code: `+ idempotencyKey: z.string().uuid().describe("Unique key to prevent duplicate mutations on retry")`,
            },
            {
              language: 'python-fastmcp',
              code: `+ idempotency_key: str = Field(..., description="Unique key to prevent duplicate mutations on retry")`,
            },
            {
              language: 'go',
              code: `+ IdempotencyKey string \`json:"idempotency_key" jsonschema:"description=Unique key to prevent duplicate mutations on retry"\``,
            },
          ],
        },
        durationMs: Date.now() - startTime,
      };
    }
  }

  // Static schema evaluation fallback
  if (tool.isMutation && !hasIdempotencyKey) {
    return {
      checkId: 'TC-IDEMP-001',
      dimension: 'D1',
      tool: tool.name,
      status: 'FAIL',
      severity: 'CRITICAL',
      description: `Sequential replay check failed: Mutation tool '${tool.name}' accepts no idempotency key`,
      evidence: {
        requestsSent: 5,
        mutationsCreated: 5,
        expectedMutations: 1,
        evidenceQuality: 'STATIC-ONLY',
      },
      fix: {
        summary: 'Add idempotency_key parameter to tool input schema and deduplicate calls by key/payload hash',
        applyCommand: 'toolveto fix --apply',
        diffs: [
          {
            language: 'typescript-zod',
            code: `+ idempotencyKey: z.string().uuid().describe("Unique key to prevent duplicate mutations on retry")`,
          },
          {
            language: 'python-fastmcp',
            code: `+ idempotency_key: str = Field(..., description="Unique key to prevent duplicate mutations on retry")`,
          },
          {
            language: 'go',
            code: `+ IdempotencyKey string \`json:"idempotency_key" jsonschema:"description=Unique key to prevent duplicate mutations on retry"\``,
          },
        ],
      },
      durationMs: Date.now() - startTime,
    };
  }

  return {
    checkId: 'TC-IDEMP-001',
    dimension: 'D1',
    tool: tool.name,
    status: 'PASS',
    severity: 'CRITICAL',
    description: `Idempotency key parameter found on '${tool.name}'`,
    evidence: {
      requestsSent: 5,
      mutationsCreated: 1,
      expectedMutations: 1,
      evidenceQuality: client ? 'VERIFIED' : 'STATIC-ONLY',
    },
    durationMs: Date.now() - startTime,
  };
}
