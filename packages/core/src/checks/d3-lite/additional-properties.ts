import { CheckResult, McpToolDefinition } from '../../types.js';

export function runAdditionalPropertiesCheck(tool: McpToolDefinition): CheckResult {
  const startTime = Date.now();
  const hasAdditionalPropsFalse = tool.inputSchema?.additionalProperties === false;

  if (!hasAdditionalPropsFalse) {
    return {
      checkId: 'TC-SCHEMA-003',
      dimension: 'D3',
      tool: tool.name,
      status: 'WARN',
      severity: 'MEDIUM',
      description: `Schema boundary vulnerability: Tool '${tool.name}' omits 'additionalProperties: false', allowing hallucinated LLM properties to leak into backend logic`,
      evidence: { evidenceQuality: 'STATIC-ONLY' },
      fix: {
        summary: "Add 'additionalProperties: false' or .strict() validation",
        applyCommand: 'toolveto fix --apply',
        diffs: [
          {
            language: 'json-schema',
            code: `+ "additionalProperties": false`,
          },
          {
            language: 'typescript-zod',
            code: `+ z.object({ ... }).strict()`,
          },
        ],
      },
      durationMs: Date.now() - startTime,
    };
  }

  return {
    checkId: 'TC-SCHEMA-003',
    dimension: 'D3',
    tool: tool.name,
    status: 'PASS',
    severity: 'LOW',
    description: `Schema boundary enforced on '${tool.name}' via 'additionalProperties: false'`,
    evidence: { evidenceQuality: 'STATIC-ONLY' },
    durationMs: Date.now() - startTime,
  };
}
