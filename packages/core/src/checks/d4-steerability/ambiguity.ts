import { CheckResult, McpToolDefinition } from '../../types.js';

export function runDescriptionAmbiguityCheck(
  tool: McpToolDefinition,
  allTools: McpToolDefinition[]
): CheckResult {
  const startTime = Date.now();
  const desc = (tool.description || '').trim();

  // 1. Check description presence and depth
  if (!desc || desc.length < 20) {
    return {
      checkId: 'TC-STEER-001',
      dimension: 'D4',
      tool: tool.name,
      status: 'WARN',
      severity: 'MEDIUM',
      description: `Steerability warning: Tool '${tool.name}' has terse description (<20 chars), risking poor tool selection across LLMs`,
      evidence: {
        evidenceQuality: 'STATIC-ONLY',
        details: { descriptionLength: desc.length },
      },
      fix: {
        summary: 'Provide detailed semantic description specifying purpose, prerequisites, and expected outcomes',
        applyCommand: 'toolveto fix --suggest',
        diffs: [
          {
            language: 'typescript-zod',
            code: `+ description: "Executes ${tool.name}. Requires valid credentials. Returns structured transaction receipt."`,
          },
        ],
      },
      durationMs: Date.now() - startTime,
    };
  }

  // 2. Check for tool name overlap / collisions
  const similarTools = allTools.filter(
    (t) => t.name !== tool.name && (t.name.includes(tool.name) || tool.name.includes(t.name))
  );

  if (similarTools.length > 0 && desc.length < 50) {
    return {
      checkId: 'TC-STEER-001',
      dimension: 'D4',
      tool: tool.name,
      status: 'WARN',
      severity: 'MEDIUM',
      description: `Steerability conflict: Tool '${tool.name}' shares naming root with [${similarTools.map((t) => t.name).join(', ')}] but lacks distinguishing description (>50 chars)`,
      evidence: {
        evidenceQuality: 'STATIC-ONLY',
        details: { similarTools: similarTools.map((t) => t.name) },
      },
      durationMs: Date.now() - startTime,
    };
  }

  return {
    checkId: 'TC-STEER-001',
    dimension: 'D4',
    tool: tool.name,
    status: 'PASS',
    severity: 'LOW',
    description: `Tool description provides sufficient semantic steerability context (${desc.length} chars)`,
    evidence: {
      evidenceQuality: 'STATIC-ONLY',
    },
    durationMs: Date.now() - startTime,
  };
}

export function runParamSteerabilityCheck(tool: McpToolDefinition): CheckResult {
  const startTime = Date.now();
  const properties = tool.inputSchema?.properties || {};
  const unguidedParams: string[] = [];

  for (const [key, prop] of Object.entries(properties)) {
    const isIdOrDate =
      key.includes('id') ||
      key.includes('date') ||
      key.includes('time') ||
      key.includes('email') ||
      key.includes('url');
    const hasFormatOrPattern = Boolean(prop.format || prop.pattern || (prop.description && prop.description.includes('e.g.')));

    if (isIdOrDate && !hasFormatOrPattern && !prop.description) {
      unguidedParams.push(key);
    }
  }

  if (unguidedParams.length > 0) {
    return {
      checkId: 'TC-STEER-002',
      dimension: 'D4',
      tool: tool.name,
      status: 'WARN',
      severity: 'LOW',
      description: `Parameter steerability: Sensitive fields [${unguidedParams.join(', ')}] lack format examples (e.g. YYYY-MM-DD or UUIDv4)`,
      evidence: {
        evidenceQuality: 'STATIC-ONLY',
        details: { unguidedParams },
      },
      durationMs: Date.now() - startTime,
    };
  }

  return {
    checkId: 'TC-STEER-002',
    dimension: 'D4',
    tool: tool.name,
    status: 'PASS',
    severity: 'LOW',
    description: `All parameters provide adequate type and format guidance for LLM prompt steerability`,
    evidence: {
      evidenceQuality: 'STATIC-ONLY',
    },
    durationMs: Date.now() - startTime,
  };
}
