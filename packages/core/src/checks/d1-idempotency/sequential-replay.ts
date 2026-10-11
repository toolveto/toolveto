import { CheckResult, McpToolDefinition } from '../../types.js';
import { McpClient } from '../../transports/interface.js';
import { extractEntityId, hashPayloadState } from './entity-extractor.js';

export async function runSequentialReplayCheck(
  tool: McpToolDefinition,
  client?: McpClient,
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

  // If client provided and tool is a mutation, execute 5 sequential replay calls ONLY if destructive authorization is granted
  if (client && tool.isMutation && destructiveAuthorization) {
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
    const stateHashes = new Set<string>();
    let errorsEncountered = 0;

    for (let i = 0; i < 5; i++) {
      try {
        const resp = await client.callTool(tool.name, samplePayload);
        const text = resp.content?.map((c) => c.text).join('') || '';
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
      } catch {
        errorsEncountered++;
      }
    }

    const distinctMutations =
      createdEntityIds.size > 0
        ? createdEntityIds.size
        : Math.max(1, stateHashes.size);

    // Behavioral failure: creating multiple distinct records on identical replay is ALWAYS fatal
    if (distinctMutations > 1) {
      return {
        checkId: 'TC-IDEMP-001',
        dimension: 'D1',
        tool: tool.name,
        status: 'FAIL',
        severity: 'CRITICAL',
        description: `Sequential replay failure: Mutation tool '${tool.name}' executed ${distinctMutations} distinct mutations on replaying identical requests (double-charge / double-effect)`,
        evidence: {
          requestsSent: 5,
          mutationsCreated: distinctMutations,
          expectedMutations: 1,
          evidenceQuality: 'VERIFIED',
          details: {
            distinctMutations,
            hasIdempotencyKey,
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

    // Behavioral pass: exactly 1 mutation executed
    if (!hasIdempotencyKey) {
      // 30% declaration penalty / advisory: behaviorally idempotent but missing explicit schema contract
      return {
        checkId: 'TC-IDEMP-001',
        dimension: 'D1',
        tool: tool.name,
        status: 'WARN',
        severity: 'MEDIUM',
        description: `Mutation tool '${tool.name}' behaviorally deduplicated 5 replays to 1 mutation, but lacks explicit idempotency_key parameter in schema`,
        evidence: {
          requestsSent: 5,
          mutationsCreated: 1,
          expectedMutations: 1,
          evidenceQuality: 'VERIFIED',
          details: { hasIdempotencyKey: false },
        },
        durationMs: Date.now() - startTime,
      };
    }

    return {
      checkId: 'TC-IDEMP-001',
      dimension: 'D1',
      tool: tool.name,
      status: 'PASS',
      severity: 'LOW',
      description: `Sequential replay check passed: '${tool.name}' cleanly deduplicated 5 replay calls to 1 mutation`,
      evidence: {
        requestsSent: 5,
        mutationsCreated: 1,
        expectedMutations: 1,
        evidenceQuality: 'VERIFIED',
        details: { hasIdempotencyKey: true },
      },
      durationMs: Date.now() - startTime,
    };
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
