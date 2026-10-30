import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { McpToolDefinition } from '@toolveto/core';

export interface ExportPolicyOptions {
  format?: 'cedar' | 'opa' | 'weaveproof' | 'weaveproof-genome' | string;
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

export function generateWeaveProofCedarPolicy(tools: McpToolDefinition[]): string {
  const blocks: string[] = [
    '// ============================================================================',
    '// ToolVeto x WeaveProof Enterprise Runtime Governance Policy Pack',
    '// Upgrades static ToolVeto D1-D5 checks with CRM @clamp ceilings,',
    '// 2-of-2 SOX Dual-Quorum HITL approvals, and Cross-MCP Taint Blocking',
    '// ============================================================================',
  ];

  for (const tool of tools) {
    const destructive = isDestructiveTool(tool);
    const readOnly = isReadOnlyTool(tool);
    const lower = tool.name.toLowerCase();
    const isFinancial = ['payment', 'refund', 'credit', 'invoice', 'transfer', 'charge', 'journal'].some((k) =>
      lower.includes(k)
    );

    if (destructive) {
      blocks.push(`
// Tool '${tool.name}' (Destructive Mutation — 2-of-2 Dual-Quorum SOX/SOC2 HITL)
@id("tv-wp-quorum-${lower.replace(/[^a-z0-9]/g, '-')}")
@approval(quorum=2, roles=["security_admin", "controller"], min_dwell_ms=800)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"${tool.name}"
) when {
  context.humanApproved == true
};`);
    } else if (isFinancial || !readOnly) {
      blocks.push(`
// Tool '${tool.name}' (Financial / State Mutation — CRM-Hydrated @clamp + Idempotency)
@id("tv-wp-clamp-${lower.replace(/[^a-z0-9]/g, '-')}")
@clamp(field="amount", limit=250000, currency="USD")
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"${tool.name}"
) when {
  context.hasIdempotencyKey == true && !context.session_taint.contains("UNTRUSTED_EXTERNAL_INGEST")
};`);
    } else {
      blocks.push(`
// Tool '${tool.name}' (Read-Only Query — Dynamic Tool Slicer Permitted)
@id("tv-wp-readonly-${lower.replace(/[^a-z0-9]/g, '-')}")
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"${tool.name}"
);`);
    }
  }

  return blocks.join('\n') + '\n';
}

export function generateWeaveProofGenomeManifest(tools: McpToolDefinition[]): string {
  const toolEntries = tools.map((tool) => {
    const destructive = isDestructiveTool(tool);
    const readOnly = isReadOnlyTool(tool);
    const lower = tool.name.toLowerCase();
    const isFinancial = ['payment', 'refund', 'credit', 'invoice', 'transfer', 'charge', 'journal'].some((k) =>
      lower.includes(k)
    );
    const canonicalString = `${tool.name}||${tool.description || ''}||${JSON.stringify(tool.inputSchema || {})}`;
    const sha256Hash = crypto.createHash('sha256').update(canonicalString).digest('hex');

    return {
      toolName: tool.name,
      canonicalSha256: `sha256:${sha256Hash}`,
      pinningFormula: 'SHA256(name || description || inputSchema)',
      failureCodeOnMismatch: -32004,
      riskTier: destructive
        ? 'DUAL_QUORUM_2OF2_ED25519'
        : isFinancial || !readOnly
        ? 'SUPERVISED_HOLD_VFENCE'
        : 'AUTO_PERMITTED_READ',
      contextSlicingEligible: readOnly && !destructive,
      requiresMonotonicLeaseFence: !readOnly || destructive,
      requiresIdempotencyKey: !readOnly || destructive,
    };
  });

  const manifest = {
    schemaVersion: 'weaveproof-genome/v1',
    protocolTarget: 'MCP-2026-07-28-Stateless-Core',
    exportedBy: '@toolveto/cli',
    exportedAt: new Date().toISOString(),
    portfolioHandoff: {
      ciGatekeeper: 'ToolVeto (D1-D5 Pre-Merge & IDE Config Certification)',
      runtimeControlPlane: 'WeaveProof Gateway (Context Slicing + Lease-Fenced HITL + WeaveDigest)',
    },
    pinnedTools: toolEntries,
  };

  return JSON.stringify(manifest, null, 2) + '\n';
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
      : format === 'weaveproof-genome' || format === 'genome'
      ? generateWeaveProofGenomeManifest(tools)
      : format === 'weaveproof'
      ? generateWeaveProofCedarPolicy(tools)
      : generateCedarPolicy(tools);

  if (options.output) {
    const outPath = path.resolve(process.cwd(), options.output);
    fs.writeFileSync(outPath, policyText, 'utf-8');
    console.log(`\n✅ Exported ${format.toUpperCase()} least-privilege policy to ${outPath}`);
    console.log(
      `💡 Enterprise Upgrade: Import into WeaveProof for live @clamp ceilings, 2-of-2 SOX HITL & SOC 2/ISO 42001 audit binders:\n` +
        `   👉 weaveproof-cli policy plan --file ${path.basename(outPath)}\n`
    );
  } else {
    console.log(policyText);
  }
}
