import { CheckResult, McpToolDefinition } from '../../types.js';

export function runPaginationSchemaCheck(tool: McpToolDefinition): CheckResult {
  const startTime = Date.now();
  const isListQuery =
    tool.name.startsWith('list_') ||
    tool.name.startsWith('get_all_') ||
    tool.name.startsWith('search_') ||
    tool.name.includes('invoices') ||
    tool.name.includes('records') ||
    tool.name.includes('items');

  const properties = tool.inputSchema?.properties || {};
  const hasPagination = Boolean(
    properties['limit'] || properties['page_size'] || properties['cursor'] || properties['offset']
  );

  if (isListQuery && !hasPagination) {
    return {
      checkId: 'TC-SCHEMA-001',
      dimension: 'D3',
      tool: tool.name,
      status: 'FAIL',
      severity: 'HIGH',
      description: `Unbounded list response risk: Query tool '${tool.name}' has no limit/cursor parameter and risks context bomb under production load`,
      evidence: {
        evidenceQuality: 'STATIC-ONLY',
        details: {
          recommendation: 'Add default limit <= 50 and cursor/has_more pagination fields to schema',
        },
      },
      fix: {
        summary: 'Add limit and cursor pagination parameters',
        applyCommand: 'toolveto fix --apply',
        diffs: [
          {
            language: 'typescript-zod',
            code: `+ limit: z.number().int().min(1).max(100).default(20).describe("Max items to return (default 20)"),\n+ cursor: z.string().optional().describe("Opaque pagination cursor")`,
          },
          {
            language: 'python-fastmcp',
            code: `+ limit: int = Field(20, ge=1, le=100, description="Max items to return (default 20)"),\n+ cursor: Optional[str] = Field(None, description="Opaque pagination cursor")`,
          },
        ],
      },
      durationMs: Date.now() - startTime,
    };
  }

  return {
    checkId: 'TC-SCHEMA-001',
    dimension: 'D3',
    tool: tool.name,
    status: 'PASS',
    severity: 'MEDIUM',
    description: `Pagination parameters properly defined on '${tool.name}'`,
    evidence: {
      evidenceQuality: 'STATIC-ONLY',
    },
    durationMs: Date.now() - startTime,
  };
}
