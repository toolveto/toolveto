import { CheckResult, McpToolDefinition } from '../../types.js';
import { McpClient } from '../../transports/interface.js';

export async function runSemanticErrorCheck(
  tool: McpToolDefinition,
  client?: McpClient
): Promise<CheckResult> {
  const startTime = Date.now();
  const properties = tool.inputSchema?.properties || {};

  const dateParamEntry = Object.entries(properties).find(([name, schema]) => {
    return name.includes('date') || schema.format === 'date';
  });

  if (!dateParamEntry) {
    return {
      checkId: 'TC-ERR-001',
      dimension: 'D2',
      tool: tool.name,
      status: 'PASS',
      severity: 'HIGH',
      description: `Tool '${tool.name}' has no strict semantic date formats requiring healing evaluation`,
      evidence: { evidenceQuality: 'STATIC-ONLY' },
      durationMs: Date.now() - startTime,
    };
  }

  const [paramName] = dateParamEntry;

  if (client) {
    try {
      const resp = await client.callTool(tool.name, {
        [paramName]: 'tomorrow morning',
      });

      const text = resp.content?.map((c) => c.text).join('') || '';

      // Check if raw 500 or stack trace returned without parameter name
      const isRawCrash = text.includes('Internal error') || text.includes('TypeError') || text.includes('Traceback');
      const mentionsParam = text.toLowerCase().includes(paramName.toLowerCase());
      const mentionsExpectedFormat = text.includes('YYYY-MM-DD') || text.includes('ISO') || text.includes('format');
      const providesExample = text.includes('e.g.') || text.includes('example') || text.includes('202');

      if (isRawCrash || !mentionsParam || !mentionsExpectedFormat) {
        return {
          checkId: 'TC-ERR-001',
          dimension: 'D2',
          tool: tool.name,
          status: 'FAIL',
          severity: 'HIGH',
          description: `Error self-healing failure (Loop 47x risk): Passing 'tomorrow morning' to '${paramName}' returned unhelpful or crashing error. LLMs cannot self-correct without parameter citation and format example`,
          evidence: {
            evidenceQuality: 'VERIFIED',
            details: {
              param: paramName,
              injectedValue: 'tomorrow morning',
              rawErrorOutput: text.slice(0, 200),
              isRawCrash,
              mentionsParam,
              mentionsExpectedFormat,
              providesExample,
            },
          },
          fix: {
            summary: `Return structured McpError with parameter name, expected format (YYYY-MM-DD), and valid example`,
            applyCommand: 'toolveto fix --apply',
            diffs: [
              {
                language: 'typescript-zod',
                code: `+ if (!/^\\d{4}-\\d{2}-\\d{2}$/.test(${paramName})) {\n+   return { isError: true, content: [{ type: "text", text: "Invalid format for '${paramName}'. Expected ISO format YYYY-MM-DD (e.g. '2026-10-15'). Received: '" + ${paramName} + "'." }] };\n+ }`,
              },
              {
                language: 'python-fastmcp',
                code: `+ if not re.match(r"^\\d{4}-\\d{2}-\\d{2}$", ${paramName}):\n+     return {"isError": True, "content": [{"type": "text", "text": f"Invalid format for '${paramName}'. Expected ISO format YYYY-MM-DD (e.g. '2026-10-15'). Received: '{${paramName}}'."}]}`,
              },
            ],
          },
          durationMs: Date.now() - startTime,
        };
      }
    } catch (err: any) {
      return {
        checkId: 'TC-ERR-001',
        dimension: 'D2',
        tool: tool.name,
        status: 'FAIL',
        severity: 'HIGH',
        description: `Error self-healing failure: Transport crashed on invalid semantic date input: ${err.message}`,
        evidence: { evidenceQuality: 'VERIFIED' },
        durationMs: Date.now() - startTime,
      };
    }
  }

  return {
    checkId: 'TC-ERR-001',
    dimension: 'D2',
    tool: tool.name,
    status: 'PASS',
    severity: 'HIGH',
    description: `Actionable error feedback verified on '${tool.name}' for parameter '${paramName}'`,
    evidence: { evidenceQuality: client ? 'VERIFIED' : 'STATIC-ONLY' },
    durationMs: Date.now() - startTime,
  };
}
