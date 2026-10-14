import * as fs from 'node:fs';
import * as path from 'node:path';
import type { McpToolDefinition } from '@toolveto/core';

export interface ExportPolicyOptions {
  format?: 'cedar' | 'opa' | string;
  output?: string;
  demo?: boolean;
}

function loadToolsForPolicy(resolvedTarget: string, demo = false): McpToolDefinition[] {
  let tools: McpToolDefinition[] = [];
  if (fs.existsSync(resolvedTarget)) {
    const stat = fs.statSync(resolvedTarget);
    if (stat.isFile() && resolvedTarget.endsWith('.json')) {
      const parsed = JSON.parse(fs.readFileSync(resolvedTarget, 'utf-8'));
      tools = Array.isArray(parsed) ? parsed : parsed.tools || [];
    } else if (stat.isDirectory()) {
      for (const candidate of ['tools.json', 'mcp.json', 'schema.json']) {
        const full = path.join(resolvedTarget, candidate);
        if (fs.existsSync(full)) {
          const parsed = JSON.parse(fs.readFileSync(full, 'utf-8'));
          tools = Array.isArray(parsed) ? parsed : parsed.tools || [];
          break;
        }
      }
    }
  }

  if (tools.length === 0 && demo) {
    tools = [
      {
        name: 'get_invoice',
        description: 'Reads customer invoice by ID',
        isMutation: false,
        readOnlyHint: true,
        inputSchema: { type: 'object', properties: { invoice_id: { type: 'string' } } },
      },
      {
        name: 'create_payment',
        description: 'Creates a payment transaction',
        isMutation: true,
        idempotentHint: true,
        inputSchema: {
          type: 'object',
          properties: { amount: { type: 'number' }, idempotency_key: { type: 'string' } },
        },
      },
      {
        name: 'delete_customer_account',
        description: 'Permanently deletes customer account',
        isMutation: true,
        destructiveHint: true,
        inputSchema: { type: 'object', properties: { customer_id: { type: 'string' } } },
      },
    ];
  }
  return tools;
}

function isDestructiveTool(tool: McpToolDefinition): boolean {
  if (tool.destructiveHint === true) return true;
  const lower = tool.name.toLowerCase();
  return ['delete', 'drop', 'remove', 'destroy', 'purge', 'revoke', 'wipe'].some((k) => lower.includes(k));
}

function isReadOnlyTool(tool: McpToolDefinition): boolean {
  if (tool.readOnlyHint === true) return true;
  if (tool.isMutation === false && !isDestructiveTool(tool)) return true;
  const lower = tool.name.toLowerCase();
  return ['get_', 'list_', 'read_', 'search_', 'query_', 'inspect_'].some((k) => lower.startsWith(k));
}

export function generateCedarPolicy(tools: McpToolDefinition[]): string {
  const blocks: string[] = [
    '// ============================================================================',
    '// ToolVeto Auto-Generated Least-Privilege AWS Cedar Policy',
    '// Standard: AIUC-1 §5.1 & OWASP Agentic Least Agency',
    '// ============================================================================',
  ];

  for (const tool of tools) {
    const destructive = isDestructiveTool(tool);
    const readOnly = isReadOnlyTool(tool);

    if (destructive) {
      blocks.push(`
// Tool '${tool.name}' (Destructive Mutation — requires human approval)
forbid (
  principal,
  action == Action::"tools/call",
  resource == Tool::"${tool.name}"
) unless {
  context.humanApproved == true
};`);
    } else if (readOnly) {
      blocks.push(`
// Tool '${tool.name}' (Read-Only Query — safe for autonomous execution)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"${tool.name}"
);`);
    } else {
      blocks.push(`
// Tool '${tool.name}' (State Mutation — requires idempotency key)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"${tool.name}"
) when {
  context.hasIdempotencyKey == true
};`);
    }
  }

  return blocks.join('\n') + '\n';
}

export function generateOpaRegoPolicy(tools: McpToolDefinition[]): string {
  const readOnlyNames = tools.filter((t) => isReadOnlyTool(t) && !isDestructiveTool(t)).map((t) => t.name);
  const destructiveNames = tools.filter((t) => isDestructiveTool(t)).map((t) => t.name);
  const mutationNames = tools
    .filter((t) => !isReadOnlyTool(t) && !isDestructiveTool(t))
    .map((t) => t.name);

  return `# ============================================================================
# ToolVeto Auto-Generated Least-Privilege Open Policy Agent (Rego) Policy
# Standard: AIUC-1 §5.1 & OWASP Agentic Least Agency
# ============================================================================
package toolveto.authz

import rego.v1

default allow := false

read_only_tools := ${JSON.stringify(readOnlyNames)}
mutation_tools := ${JSON.stringify(mutationNames)}
destructive_tools := ${JSON.stringify(destructiveNames)}

# Allow read-only inspection tools unconditionally
allow if {
  input.method == "tools/call"
  input.params.name in read_only_tools
}

# Allow standard state mutations only when idempotency_key is provided
allow if {
  input.method == "tools/call"
  input.params.name in mutation_tools
  input.params.arguments.idempotency_key != ""
}

# Allow destructive tools only with explicit human-in-the-loop approval
allow if {
  input.method == "tools/call"
  input.params.name in destructive_tools
  input.context.human_approved == true
}
`;
}

export async function exportPolicyCommand(
  targetPath?: string,
  options: ExportPolicyOptions = {}
): Promise<void> {
  const resolvedTarget = path.resolve(process.cwd(), targetPath || '.');
  const format = (options.format || 'cedar').toLowerCase();
  const tools = loadToolsForPolicy(resolvedTarget, options.demo);

  if (tools.length === 0) {
    console.error(`\n❌ Error: No tools discovered at '${targetPath || '.'}' for policy generation.`);
    process.exitCode = 1;
    return;
  }

  const policyText =
    format === 'opa' || format === 'rego'
      ? generateOpaRegoPolicy(tools)
      : generateCedarPolicy(tools);

  if (options.output) {
    const outPath = path.resolve(process.cwd(), options.output);
    fs.writeFileSync(outPath, policyText, 'utf-8');
    console.log(`\n✅ Exported ${format.toUpperCase()} least-privilege policy to ${outPath}\n`);
  } else {
    console.log(policyText);
  }
}
