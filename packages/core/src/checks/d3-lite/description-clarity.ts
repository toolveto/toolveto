import { CheckResult, McpToolDefinition } from '../../types.js';

export function runDescriptionClarityCheck(tool: McpToolDefinition): CheckResult {
  const startTime = Date.now();
  const desc = (tool.description || '').trim();

  if (desc.length < 30) {
    return {
      checkId: 'TC-SCHEMA-002',
      dimension: 'D3',
      tool: tool.name,
      status: 'FAIL',
      severity: 'MEDIUM',
      description: `Description entropy failure: Tool '${tool.name}' description is too terse (${desc.length} chars, minimum 30 required for reliable LLM tool steering)`,
      evidence: {
        evidenceQuality: 'STATIC-ONLY',
        details: { descriptionLength: desc.length, currentDescription: desc },
      },
      fix: {
        summary: 'Expand tool description with operational purpose, constraints, and side effects',
        applyCommand: 'toolveto fix --apply',
        diffs: [
          {
            language: 'json-schema',
            code: `+ "description": "${desc}. Detailed explanation of tool purpose, parameters, and return shape."`,
          },
        ],
      },
      durationMs: Date.now() - startTime,
    };
  }

  return {
    checkId: 'TC-SCHEMA-002',
    dimension: 'D3',
    tool: tool.name,
    status: 'PASS',
    severity: 'LOW',
    description: `Tool description clarity adequate (${desc.length} chars)`,
    evidence: { evidenceQuality: 'STATIC-ONLY' },
    durationMs: Date.now() - startTime,
  };
}
