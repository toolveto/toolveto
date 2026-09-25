import { CheckResult, McpToolDefinition } from '../../types.js';

export function runReadBeforeWritePairingCheck(
  tool: McpToolDefinition,
  allTools: McpToolDefinition[]
): CheckResult {
  const startTime = Date.now();

  if (!tool.isMutation) {
    return {
      checkId: 'TC-PAIR-001',
      dimension: 'D5',
      tool: tool.name,
      status: 'PASS',
      severity: 'LOW',
      description: `Query tool '${tool.name}' is an inspection tool`,
      evidence: { evidenceQuality: 'STATIC-ONLY' },
      durationMs: Date.now() - startTime,
    };
  }

  // Derive target entity from mutation tool name (e.g. create_payment -> payment, update_appointment -> appointment)
  const entityName = tool.name
    .replace(/^(create_|update_|delete_|set_|modify_|post_|add_)/, '');

  const hasCompanionQuery = allTools.some((t) => {
    if (t.isMutation) return false;
    const qName = t.name.toLowerCase();
    return (
      qName === `get_${entityName}` ||
      qName === `read_${entityName}` ||
      qName === `inspect_${entityName}` ||
      qName === `find_${entityName}` ||
      qName === `list_${entityName}s` ||
      qName === `get_${entityName}s`
    );
  });

  if (!hasCompanionQuery) {
    return {
      checkId: 'TC-PAIR-001',
      dimension: 'D5',
      tool: tool.name,
      status: 'FAIL',
      severity: 'HIGH',
      description: `State auditability blind-write violation: Mutation tool '${tool.name}' lacks companion query tool ('get_${entityName}' or 'read_${entityName}'). Agents cannot verify pre/post state changes`,
      evidence: {
        evidenceQuality: 'STATIC-ONLY',
        details: { targetEntity: entityName, expectedCompanion: `get_${entityName}` },
      },
      fix: {
        summary: `Expose a companion read-only query tool 'get_${entityName}' accepting primary entity ID`,
        applyCommand: 'toolveto fix --apply',
        diffs: [
          {
            language: 'typescript-zod',
            code: `+ // Define companion inspection query tool:\n+ server.tool("get_${entityName}", { ${entityName}_id: z.string() }, async ({ ${entityName}_id }) => {\n+   return { content: [{ type: "text", text: JSON.stringify(await db.get(${entityName}_id)) }] };\n+ });`,
          },
        ],
      },
      durationMs: Date.now() - startTime,
    };
  }

  return {
    checkId: 'TC-PAIR-001',
    dimension: 'D5',
    tool: tool.name,
    status: 'PASS',
    severity: 'LOW',
    description: `Read-before-write inspection companion verified for '${tool.name}'`,
    evidence: { evidenceQuality: 'STATIC-ONLY' },
    durationMs: Date.now() - startTime,
  };
}
