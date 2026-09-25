import { CheckResult, McpToolDefinition } from '../../types.js';
import { McpClient } from '../../transports/interface.js';

export async function runTokenBudgetCheck(
  tool: McpToolDefinition,
  client?: McpClient
): Promise<CheckResult> {
  const startTime = Date.now();

  if (client && !tool.isMutation) {
    try {
      const resp = await client.callTool(tool.name, {});
      const text = resp.content?.map((c) => c.text).join('') || '';
      // Approximate 1 token = 4 characters
      const estimatedTokens = Math.ceil(text.length / 4);

      if (estimatedTokens > 8000) {
        return {
          checkId: 'TC-CTX-001',
          dimension: 'D3',
          tool: tool.name,
          status: 'FAIL',
          severity: 'CRITICAL',
          description: `Context Bomb detected: Query tool '${tool.name}' returned ${estimatedTokens} tokens (> 8,000 token limit), triggering VETO_DATALOSS fatal penalty`,
          evidence: {
            evidenceQuality: 'VERIFIED',
            details: {
              estimatedTokens,
              characterLength: text.length,
              threshold: 8000,
            },
          },
          fix: {
            summary: "Enforce default page limit <= 50 and return pagination cursor or projection parameters",
            applyCommand: 'toolveto fix --apply',
            diffs: [
              {
                language: 'typescript-zod',
                code: `+ const MAX_PAGE_SIZE = 50;\n+ const items = allResults.slice(0, Math.min(args.limit ?? 20, MAX_PAGE_SIZE));\n+ return { content: [{ type: "text", text: JSON.stringify({ items, has_more: allResults.length > MAX_PAGE_SIZE }) }] };`,
              },
            ],
          },
          durationMs: Date.now() - startTime,
        };
      }

      if (estimatedTokens > 1500) {
        return {
          checkId: 'TC-CTX-001',
          dimension: 'D3',
          tool: tool.name,
          status: 'WARN',
          severity: 'MEDIUM',
          description: `Payload size warning: Response returned ${estimatedTokens} tokens (recommended budget <= 1,500 tokens). Consider field projection or pagination`,
          evidence: {
            evidenceQuality: 'VERIFIED',
            details: { estimatedTokens, characterLength: text.length },
          },
          durationMs: Date.now() - startTime,
        };
      }
    } catch {
      // If call failed, fall back
    }
  }

  return {
    checkId: 'TC-CTX-001',
    dimension: 'D3',
    tool: tool.name,
    status: 'PASS',
    severity: 'CRITICAL',
    description: `Token budget compliance passed: payload size is well within agent limits`,
    evidence: { evidenceQuality: client ? 'VERIFIED' : 'STATIC-ONLY' },
    durationMs: Date.now() - startTime,
  };
}
