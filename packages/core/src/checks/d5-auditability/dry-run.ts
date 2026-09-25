import { CheckResult, McpToolDefinition } from '../../types.js';

export function runDryRunCheck(tool: McpToolDefinition): CheckResult {
  const startTime = Date.now();

  if (!tool.isMutation) {
    return {
      checkId: 'TC-DRYRUN-001',
      dimension: 'D5',
      tool: tool.name,
      status: 'PASS',
      severity: 'LOW',
      description: `Query tool '${tool.name}' has no side-effects and does not require dry_run parameter`,
      evidence: { evidenceQuality: 'STATIC-ONLY' },
      durationMs: Date.now() - startTime,
    };
  }

  const properties = tool.inputSchema?.properties || {};
  const hasDryRun = Boolean(
    properties['dry_run'] ||
    properties['dryRun'] ||
    properties['validate_only'] ||
    properties['simulate']
  );

  if (!hasDryRun) {
    return {
      checkId: 'TC-DRYRUN-001',
      dimension: 'D5',
      tool: tool.name,
      status: 'WARN',
      severity: 'MEDIUM',
      description: `Dry-run transaction simulation missing on mutation tool '${tool.name}'. Agents cannot preview side-effects before persisting real mutations`,
      evidence: { evidenceQuality: 'STATIC-ONLY' },
      fix: {
        summary: "Add optional 'dry_run: boolean' parameter to allow safe execution preview",
        applyCommand: 'toolveto fix --apply',
        diffs: [
          {
            language: 'typescript-zod',
            code: `+ dry_run: z.boolean().optional().describe("If true, validates transaction without persisting state changes")`,
          },
        ],
      },
      durationMs: Date.now() - startTime,
    };
  }

  return {
    checkId: 'TC-DRYRUN-001',
    dimension: 'D5',
    tool: tool.name,
    status: 'PASS',
    severity: 'LOW',
    description: `Dry-run execution simulation supported on '${tool.name}'`,
    evidence: { evidenceQuality: 'STATIC-ONLY' },
    durationMs: Date.now() - startTime,
  };
}
