import { CheckResult, McpToolDefinition } from '../../types.js';
import { McpClient } from '../../transports/interface.js';

export async function runHallucinatedParamsCheck(
  tool: McpToolDefinition,
  client?: McpClient
): Promise<CheckResult> {
  const startTime = Date.now();
  const hallucinatedKeys = ['verbose', 'force', 'dry_run', 'callback_url', 'format'];

  if (client) {
    const payload: Record<string, any> = {};
    for (const key of hallucinatedKeys) {
      payload[key] = true;
    }

    try {
      const resp = await client.callTool(tool.name, payload);
      // Tool should either ignore safely or return a handled schema rejection
      const text = resp.content?.map((c) => c.text).join('') || '';
      if (text.includes('Traceback') || text.includes('TypeError') || text.includes('-32603')) {
        return {
          checkId: 'TC-FUZZ-002',
          dimension: 'D2',
          tool: tool.name,
          status: 'FAIL',
          severity: 'HIGH',
          description: `Hallucinated parameter attack caused internal error on '${tool.name}'`,
          evidence: { evidenceQuality: 'VERIFIED', details: { injectedKeys: hallucinatedKeys, output: text.slice(0, 150) } },
          fix: {
            summary: "Set 'additionalProperties: false' in schema to safely reject or strip unmodeled arguments",
            applyCommand: 'toolveto fix --apply',
            diffs: [
              {
                language: 'typescript-zod',
                code: `+ .strict() // rejects unexpected keys in Zod`,
              },
            ],
          },
          durationMs: Date.now() - startTime,
        };
      }
    } catch (err: any) {
      return {
        checkId: 'TC-FUZZ-002',
        dimension: 'D2',
        tool: tool.name,
        status: 'FAIL',
        severity: 'HIGH',
        description: `Hallucinated parameters crashed connection on '${tool.name}': ${err.message}`,
        evidence: { evidenceQuality: 'VERIFIED' },
        durationMs: Date.now() - startTime,
      };
    }
  }

  // Static check: does schema set additionalProperties: false?
  const hasAdditionalPropsFalse = tool.inputSchema?.additionalProperties === false;
  if (!hasAdditionalPropsFalse && !client) {
    return {
      checkId: 'TC-FUZZ-002',
      dimension: 'D2',
      tool: tool.name,
      status: 'WARN',
      severity: 'MEDIUM',
      description: `Tool '${tool.name}' does not specify 'additionalProperties: false', allowing hallucinated LLM arguments through`,
      evidence: { evidenceQuality: 'STATIC-ONLY' },
      fix: {
        summary: "Add 'additionalProperties: false' to inputSchema",
        applyCommand: 'toolveto fix --apply',
        diffs: [
          {
            language: 'json-schema',
            code: `+ "additionalProperties": false`,
          },
        ],
      },
      durationMs: Date.now() - startTime,
    };
  }

  return {
    checkId: 'TC-FUZZ-002',
    dimension: 'D2',
    tool: tool.name,
    status: 'PASS',
    severity: 'MEDIUM',
    description: `Tool '${tool.name}' safely tolerates or rejects hallucinated arguments`,
    evidence: { evidenceQuality: client ? 'VERIFIED' : 'STATIC-ONLY' },
    durationMs: Date.now() - startTime,
  };
}
