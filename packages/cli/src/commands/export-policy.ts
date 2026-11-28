import * as fs from 'node:fs';
import * as path from 'node:path';
import { analyzeToxicFlow, type McpToolDefinition } from '@toolveto/core';
import { computeToolDefinitionHash } from '@toolveto/shield';
import { discoverToolsFromTarget } from '../discovery.js';
import { notifyOnboardingStep } from '../telemetry.js';

export interface ExportPolicyOptions {
  format?:
    | 'cedar'
    | 'opa'
    | 'rego'
    | 'weaveproof'
    | 'weaveproof-genome'
    | 'genome'
    | 'nvidia-openshell'
    | 'openshell'
    | 'nemo-guardrails'
    | 'nemo'
    | 'colang'
    | string;
  output?: string;
  demo?: boolean;
  allowExec?: boolean;
  apiUrl?: string;
  licenseKey?: string;
}

const DEMO_POLICY_TOOLS: McpToolDefinition[] = [
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

function escapeCedarString(val: string): string {
  return String(val)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n');
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
    const safeName = escapeCedarString(tool.name);

    if (destructive) {
      blocks.push(`
// Tool '${safeName}' (Destructive Mutation — requires human approval)
forbid (
  principal,
  action == Action::"tools/call",
  resource == Tool::"${safeName}"
) unless {
  context.humanApproved == true
};`);
    } else if (readOnly) {
      blocks.push(`
// Tool '${safeName}' (Read-Only Query — safe for autonomous execution)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"${safeName}"
);`);
    } else {
      blocks.push(`
// Tool '${safeName}' (State Mutation — requires idempotency key)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"${safeName}"
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
  const toxicAnalysis = analyzeToxicFlow(tools);
  const untrustedIngestSet = new Set(toxicAnalysis.untrustedIngestTools.map((t) => t.toolName));
  const egressSet = new Set(toxicAnalysis.externalEgressTools.map((t) => t.toolName));

  const blocks: string[] = [
    '// ============================================================================',
    '// ToolVeto x WeaveProof Enterprise Runtime Governance Policy Pack',
    '// Upgrades static ToolVeto D1-D5 checks with CRM @clamp ceilings,',
    '// 2-of-2 SOX Dual-Quorum HITL approvals, and Cross-MCP Taint Blocking',
    `// Lethal Trifecta Analysis: ${toxicAnalysis.lethalTrifectaDetected ? `CRITICAL (${toxicAnalysis.toxicPaths.length} chain(s) neutralized)` : `Risk ${toxicAnalysis.riskLevel}`}`,
    '// ============================================================================',
  ];

  for (const tool of tools) {
    const destructive = isDestructiveTool(tool);
    const readOnly = isReadOnlyTool(tool);
    const isUntrustedIngest = untrustedIngestSet.has(tool.name);
    const isExternalEgress = egressSet.has(tool.name);
    const lower = tool.name.toLowerCase();
    const safeName = escapeCedarString(tool.name);
    const safeIdSlug = lower.replace(/[^a-z0-9]/g, '-');
    const isFinancial = ['payment', 'refund', 'credit', 'invoice', 'transfer', 'charge', 'journal'].some((k) =>
      lower.includes(k)
    );

    if (isUntrustedIngest) {
      blocks.push(`
// Tool '${safeName}' (Untrusted External Ingest — marks session taint for WeaveProof Gateway)
@id("tv-wp-taint-source-${safeIdSlug}")
@taint_source("UNTRUSTED_EXTERNAL_INGEST")
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"${safeName}"
);`);
    } else if (destructive) {
      blocks.push(`
// Tool '${safeName}' (Destructive Mutation — 2-of-2 Dual-Quorum SOX/SOC2 HITL + Taint Guard)
@id("tv-wp-quorum-${safeIdSlug}")
@approval(quorum=2, roles=["security_admin", "controller"], min_dwell_ms=800)
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"${safeName}"
) when {
  context.humanApproved == true && !context.session_taint.contains("UNTRUSTED_EXTERNAL_INGEST")
};`);
    } else if (isFinancial || isExternalEgress || !readOnly) {
      blocks.push(`
// Tool '${safeName}' (Financial / Egress / State Mutation — CRM-Hydrated @clamp + Idempotency + Taint Guard)
@id("tv-wp-clamp-${safeIdSlug}")
@clamp(field="amount", limit=250000, currency="USD")
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"${safeName}"
) when {
  context.hasIdempotencyKey == true && !context.session_taint.contains("UNTRUSTED_EXTERNAL_INGEST")
};`);
    } else {
      blocks.push(`
// Tool '${safeName}' (Read-Only Query — Dynamic Tool Slicer Permitted)
@id("tv-wp-readonly-${safeIdSlug}")
permit (
  principal,
  action == Action::"tools/call",
  resource == Tool::"${safeName}"
);`);
    }
  }

  return blocks.join('\n') + '\n';
}

export function generateWeaveProofGenomeManifest(tools: McpToolDefinition[]): string {
  const toxicAnalysis = analyzeToxicFlow(tools);
  const untrustedIngestSet = new Set(toxicAnalysis.untrustedIngestTools.map((t) => t.toolName));
  const egressSet = new Set(toxicAnalysis.externalEgressTools.map((t) => t.toolName));

  const toolEntries = tools.map((tool) => {
    const destructive = isDestructiveTool(tool);
    const readOnly = isReadOnlyTool(tool);
    const lower = tool.name.toLowerCase();
    const isFinancial = ['payment', 'refund', 'credit', 'invoice', 'transfer', 'charge', 'journal'].some((k) =>
      lower.includes(k)
    );
    const rawHash = computeToolDefinitionHash(tool as any);
    const canonicalSha256 = rawHash.startsWith('sha256:') ? rawHash : `sha256:${rawHash}`;

    return {
      toolName: tool.name,
      canonicalSha256,
      pinningFormula: 'RFC8785-SHA256(normalizedToolDefinition)',
      failureCodeOnMismatch: -32004,
      riskTier: destructive
        ? 'DUAL_QUORUM_2OF2_ED25519'
        : isFinancial || !readOnly
          ? 'SUPERVISED_HOLD_VFENCE'
          : 'AUTO_PERMITTED_READ',
      contextSlicingEligible: readOnly && !destructive,
      requiresMonotonicLeaseFence: !readOnly || destructive,
      requiresIdempotencyKey: !readOnly || destructive,
      taintSourceLabel: untrustedIngestSet.has(tool.name) ? 'UNTRUSTED_EXTERNAL_INGEST' : undefined,
      blockWhenSessionTainted: egressSet.has(tool.name) || destructive || isFinancial || !readOnly,
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
    toxicFlowSummary: {
      lethalTrifectaDetected: toxicAnalysis.lethalTrifectaDetected,
      riskLevel: toxicAnalysis.riskLevel,
      chainCount: toxicAnalysis.toxicPaths.length,
    },
    pinnedTools: toolEntries,
  };

  return JSON.stringify(manifest, null, 2) + '\n';
}

function sanitizeControlAndAnsi(raw: string): string {
  return String(raw || '')
    // Strip ANSI escape sequences and non-printable control characters
    .replace(/\x1b\[[0-9;]*[A-Za-z]/g, '')
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, ' ')
    .replace(/\r?\n/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function yamlQuoted(raw: string): string {
  return JSON.stringify(sanitizeControlAndAnsi(raw));
}

function yamlKeySlug(raw: string): string {
  const slug = String(raw || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
  return slug || 'mcp_tool';
}

function colangQuoted(raw: string): string {
  return JSON.stringify(sanitizeControlAndAnsi(raw));
}

function isPrivateOrMetadataHost(hostname: string): boolean {
  const h = hostname.trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!h) return true;
  if (
    h === 'localhost' ||
    h === '0.0.0.0' ||
    h === '::1' ||
    h === '::' ||
    h.endsWith('.local') ||
    h.endsWith('.internal') ||
    h.endsWith('.localhost') ||
    h === 'metadata.google.internal'
  ) {
    return true;
  }
  const ipv4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const [a, b] = [Number(ipv4[1]), Number(ipv4[2])];
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
  }
  return false;
}

function extractSafePublicHostsFromTool(tool: McpToolDefinition): string[] {
  const blob = [tool.description || '', JSON.stringify(tool.inputSchema || {})].join(' ');
  const hosts = new Set<string>();
  const urlMatches = blob.match(/https?:\/\/[a-zA-Z0-9._:-]+/g) || [];
  for (const rawUrl of urlMatches) {
    try {
      const parsed = new URL(rawUrl);
      const host = parsed.hostname.toLowerCase();
      if (host.includes('.') && !isPrivateOrMetadataHost(host) && /^[a-z0-9.-]+$/.test(host)) {
        hosts.add(host);
      }
    } catch {
      // Ignore malformed URLs in tool docs
    }
  }
  return Array.from(hosts).sort();
}

export function generateNvidiaOpenShellPolicy(tools: McpToolDefinition[]): string {
  const toxicAnalysis = analyzeToxicFlow(tools);
  const untrustedIngestSet = new Set(toxicAnalysis.untrustedIngestTools.map((t) => t.toolName));
  const egressSet = new Set(toxicAnalysis.externalEgressTools.map((t) => t.toolName));

  const readOnlyCount = tools.filter((t) => isReadOnlyTool(t) && !isDestructiveTool(t)).length;
  const destructiveCount = tools.filter((t) => isDestructiveTool(t)).length;
  const mutationCount = tools.length - readOnlyCount - destructiveCount;

  const lines: string[] = [
    '# ============================================================================',
    '# ToolVeto Auto-Generated NVIDIA OpenShell Sandbox Policy (v1)',
    '# Standard: AIUC-1 §5.1, OWASP Agentic Least Agency & MCP Tool Pinning',
    `# Tool Classification: ${readOnlyCount} read-only, ${mutationCount} idempotent mutation, ${destructiveCount} destructive HITL`,
    `# Lethal Trifecta Analysis: ${toxicAnalysis.lethalTrifectaDetected ? `CRITICAL (${toxicAnalysis.toxicPaths.length} chain(s) blocked)` : `Risk ${toxicAnalysis.riskLevel}`}`,
    '# Apply via: openshell policy set <sandbox-name> --policy openshell-policy.yaml --wait',
    '# ============================================================================',
    'version: 1',
    '',
    'filesystem_policy:',
    '  include_workdir: true',
    '  read_only:',
    '    - "/usr"',
    '    - "/lib"',
    '    - "/proc"',
    '    - "/dev/urandom"',
    '    - "/app"',
    '    - "/etc"',
    '  read_write:',
    '    - "/tmp"',
    '    - "/dev/null"',
    '',
    'landlock:',
    '  compatibility: "best_effort"',
    '',
    'process:',
    '  run_as_user: "sandbox"',
    '  run_as_group: "sandbox"',
    '',
    '# Network policies are deny-by-default. Destructive and Lethal-Trifecta egress tools',
    '# are never granted automatic outbound endpoints.',
    'network_policies:',
  ];

  let emittedNetworkRule = false;
  const usedRuleKeys = new Set<string>();
  for (const tool of tools) {
    const destructive = isDestructiveTool(tool);
    const readOnly = isReadOnlyTool(tool);
    const isTaintedEgress = toxicAnalysis.lethalTrifectaDetected && egressSet.has(tool.name);
    if (destructive || isTaintedEgress) continue;

    const hosts = extractSafePublicHostsFromTool(tool);
    if (hosts.length === 0) continue;

    let ruleKey = `mcp_${yamlKeySlug(tool.name)}`;
    let suffix = 2;
    while (usedRuleKeys.has(ruleKey)) {
      ruleKey = `mcp_${yamlKeySlug(tool.name)}_${suffix++}`;
    }
    usedRuleKeys.add(ruleKey);
    emittedNetworkRule = true;

    lines.push(`  ${ruleKey}:`);
    lines.push(`    name: ${yamlQuoted(`toolveto-${yamlKeySlug(tool.name)}`)}`);
    lines.push('    endpoints:');
    for (const host of hosts) {
      lines.push(`      - host: ${yamlQuoted(host)}`);
      lines.push('        port: 443');
      lines.push('        protocol: "rest"');
      lines.push('        enforcement: "enforce"');
      lines.push(`        access: ${readOnly ? '"read-only"' : '"read-write"'}`);
    }
    lines.push('    binaries:');
    lines.push('      - path: "/usr/bin/node"');
    lines.push('      - path: "/usr/bin/python3"');
  }

  if (!emittedNetworkRule) {
    lines.push('  {}');
  }

  lines.push('');
  lines.push('x_toolveto_governance:');
  lines.push('  schema_version: "toolveto-openshell/v1"');
  lines.push('  exported_by: "@toolveto/cli"');
  lines.push(`  lethal_trifecta_detected: ${toxicAnalysis.lethalTrifectaDetected ? 'true' : 'false'}`);
  lines.push(`  risk_level: ${yamlQuoted(toxicAnalysis.riskLevel)}`);
  lines.push('  default_max_response_tokens: 4000');
  lines.push('  pinned_tools:');

  for (const tool of tools) {
    const destructive = isDestructiveTool(tool);
    const readOnly = isReadOnlyTool(tool);
    const rawHash = computeToolDefinitionHash(tool as any);
    const canonicalSha256 = rawHash.startsWith('sha256:') ? rawHash : `sha256:${rawHash}`;
    const isUntrustedIngest = untrustedIngestSet.has(tool.name);
    const isExternalEgress = egressSet.has(tool.name);
    const tier = destructive ? 'destructive_hitl' : readOnly ? 'read_only' : 'mutation_idempotent';

    lines.push(`    - name: ${yamlQuoted(tool.name)}`);
    lines.push(`      sha256: ${yamlQuoted(canonicalSha256)}`);
    lines.push(`      tier: ${yamlQuoted(tier)}`);
    lines.push(`      requires_idempotency_key: ${!readOnly || destructive ? 'true' : 'false'}`);
    lines.push(`      requires_human_approval: ${destructive ? 'true' : 'false'}`);
    lines.push(`      taint_source: ${isUntrustedIngest ? 'true' : 'false'}`);
    lines.push(`      block_on_session_taint: ${isExternalEgress || destructive || !readOnly ? 'true' : 'false'}`);
    lines.push('      max_response_tokens: 4000');
  }

  return lines.join('\n') + '\n';
}

export function generateNemoGuardrailsConfigYaml(tools: McpToolDefinition[]): string {
  const toxicAnalysis = analyzeToxicFlow(tools);
  const readOnlyNames = tools.filter((t) => isReadOnlyTool(t) && !isDestructiveTool(t)).map((t) => t.name);
  const destructiveNames = tools.filter((t) => isDestructiveTool(t)).map((t) => t.name);
  const mutationNames = tools
    .filter((t) => !isReadOnlyTool(t) && !isDestructiveTool(t))
    .map((t) => t.name);
  const untrustedIngestNames = toxicAnalysis.untrustedIngestTools.map((t) => t.toolName);
  const externalEgressNames = toxicAnalysis.externalEgressTools.map((t) => t.toolName);

  const lines: string[] = [
    '# ============================================================================',
    '# ToolVeto Auto-Generated NVIDIA NeMo Guardrails Configuration (config.yml)',
    '# Deterministic Tool Input/Execution/Output Rails for NeMo Agent Toolkit & FastMCP',
    `# Lethal Trifecta Analysis: ${toxicAnalysis.lethalTrifectaDetected ? `CRITICAL (${toxicAnalysis.toxicPaths.length} chain(s) neutralized)` : `Risk ${toxicAnalysis.riskLevel}`}`,
    '# Load via: RailsConfig.from_path("./nemo-guardrails")',
    '# ============================================================================',
    'models:',
    '  - type: "main"',
    '    engine: "nim"',
    '    model: "meta/llama-3.3-70b-instruct"',
    '    parameters:',
    '      tools:',
  ];

  for (const tool of tools) {
    const rawHash = computeToolDefinitionHash(tool as any);
    const canonicalSha256 = rawHash.startsWith('sha256:') ? rawHash : `sha256:${rawHash}`;
    const props = (tool.inputSchema && typeof tool.inputSchema === 'object' ? (tool.inputSchema as any).properties : {}) || {};
    const required = Array.isArray((tool.inputSchema as any)?.required) ? (tool.inputSchema as any).required : [];

    lines.push('        - type: "function"');
    lines.push('          function:');
    lines.push(`            name: ${yamlQuoted(tool.name)}`);
    lines.push(`            description: ${yamlQuoted(tool.description || `MCP tool ${tool.name}`)}`);
    lines.push(`            x_toolveto_sha256: ${yamlQuoted(canonicalSha256)}`);
    lines.push('            parameters:');
    lines.push('              type: "object"');
    const propEntries = Object.entries<any>(props);
    if (propEntries.length === 0) {
      lines.push('              properties: {}');
    } else {
      lines.push('              properties:');
      for (const [propName, propDef] of propEntries) {
        const propType = typeof propDef?.type === 'string' ? propDef.type : 'string';
        lines.push(`                ${yamlQuoted(propName)}:`);
        lines.push(`                  type: ${yamlQuoted(propType)}`);
        if (typeof propDef?.description === 'string' && propDef.description.trim()) {
          lines.push(`                  description: ${yamlQuoted(propDef.description)}`);
        }
      }
    }
    if (required.length > 0) {
      lines.push('              required:');
      for (const reqField of required) {
        lines.push(`                - ${yamlQuoted(String(reqField))}`);
      }
    }
  }

  const pushYamlList = (indent: string, key: string, items: string[]) => {
    if (items.length === 0) {
      lines.push(`${indent}${key}: []`);
      return;
    }
    lines.push(`${indent}${key}:`);
    for (const item of items) {
      lines.push(`${indent}  - ${yamlQuoted(item)}`);
    }
  };

  lines.push('');
  lines.push('rails:');
  lines.push('  input:');
  lines.push('    flows:');
  lines.push('      - "enforce toolveto input prompt hygiene"');
  lines.push('      - "jailbreak detection heuristics"');
  lines.push('  execution:');
  lines.push('    flows:');
  lines.push('      - "enforce toolveto destructive hitl"');
  lines.push('      - "enforce toolveto idempotency key"');
  lines.push('      - "enforce toolveto lethal trifecta taint"');
  lines.push('  output:');
  lines.push('    flows:');
  lines.push('      - "enforce toolveto token budget"');
  lines.push('      - "self check output"');
  lines.push('');
  lines.push('custom_data:');
  lines.push('  toolveto:');
  lines.push('    schema_version: "toolveto-nemo-guardrails/v1"');
  lines.push('    max_output_tokens: 4000');
  lines.push(`    lethal_trifecta_detected: ${toxicAnalysis.lethalTrifectaDetected ? 'true' : 'false'}`);
  lines.push(`    risk_level: ${yamlQuoted(toxicAnalysis.riskLevel)}`);
  pushYamlList('    ', 'read_only_tools', readOnlyNames);
  pushYamlList('    ', 'mutation_tools', mutationNames);
  pushYamlList('    ', 'destructive_tools', destructiveNames);
  pushYamlList('    ', 'untrusted_ingest_tools', untrustedIngestNames);
  pushYamlList('    ', 'external_egress_tools', externalEgressNames);
  lines.push('    tool_hashes:');
  for (const tool of tools) {
    const rawHash = computeToolDefinitionHash(tool as any);
    const canonicalSha256 = rawHash.startsWith('sha256:') ? rawHash : `sha256:${rawHash}`;
    lines.push(`      ${yamlQuoted(tool.name)}: ${yamlQuoted(canonicalSha256)}`);
  }

  return lines.join('\n') + '\n';
}

export function generateNemoGuardrailsColang(tools: McpToolDefinition[]): string {
  const toxicAnalysis = analyzeToxicFlow(tools);
  const destructiveNames = tools.filter((t) => isDestructiveTool(t)).map((t) => t.name);
  const mutationNames = tools
    .filter((t) => !isReadOnlyTool(t) && !isDestructiveTool(t))
    .map((t) => t.name);
  const untrustedIngestNames = toxicAnalysis.untrustedIngestTools.map((t) => t.toolName);
  const externalEgressNames = toxicAnalysis.externalEgressTools.map((t) => t.toolName);
  const taintBlockedNames = Array.from(new Set([...externalEgressNames, ...destructiveNames, ...mutationNames]));

  const formatColangList = (items: string[]) => `[${items.map((x) => colangQuoted(x)).join(', ')}]`;

  return `# ============================================================================
# ToolVeto Auto-Generated NVIDIA NeMo Guardrails Colang Flows (toolveto_rails.co)
# Deterministic zero-LLM-latency tool execution & token-budget guardrails
# ============================================================================

define bot refuse destructive tool without approval
  "Blocked by ToolVeto policy: destructive tool execution requires explicit human approval."

define bot refuse missing idempotency key
  "Blocked by ToolVeto policy: state-mutating tool calls require a non-empty idempotency_key."

define bot refuse tainted egress flow
  "Blocked by ToolVeto Lethal Trifecta policy: sensitive mutation/egress is blocked after untrusted ingest."

define flow enforce toolveto input prompt hygiene
  $blocked_patterns = ["ignore previous instructions", "system prompt override", "reveal secret key"]
  if $user_message
    $is_injected = execute toolveto_check_prompt_injection(text=$user_message, patterns=$blocked_patterns)
    if $is_injected
      bot refuse tainted egress flow
      stop

define flow enforce toolveto destructive hitl
  $destructive_tools = ${formatColangList(destructiveNames)}
  if $tool_name in $destructive_tools
    if not $human_approved
      bot refuse destructive tool without approval
      stop

define flow enforce toolveto idempotency key
  $mutation_tools = ${formatColangList(mutationNames)}
  if $tool_name in $mutation_tools
    if not $tool_arguments or not $tool_arguments.get("idempotency_key")
      bot refuse missing idempotency key
      stop

define flow enforce toolveto lethal trifecta taint
  $untrusted_ingest_tools = ${formatColangList(untrustedIngestNames)}
  $taint_blocked_tools = ${formatColangList(taintBlockedNames)}
  if $tool_name in $untrusted_ingest_tools
    $session_tainted = True
  if $session_tainted and $tool_name in $taint_blocked_tools
    bot refuse tainted egress flow
    stop

define flow enforce toolveto token budget
  $max_output_tokens = 4000
  if $tool_output
    $tool_output = execute toolveto_truncate_output(payload=$tool_output, max_tokens=$max_output_tokens)
`;
}

export function generateNemoGuardrailsBundle(tools: McpToolDefinition[]): {
  configYaml: string;
  colangFlows: string;
  combinedText: string;
} {
  const configYaml = generateNemoGuardrailsConfigYaml(tools);
  const colangFlows = generateNemoGuardrailsColang(tools);
  const combinedText = `${configYaml}\n# === toolveto_rails.co ===\n${colangFlows}`;
  return { configYaml, colangFlows, combinedText };
}

export async function exportPolicyCommand(
  targetPath?: string,
  options: ExportPolicyOptions = {}
): Promise<void> {
  const target = targetPath || '.';
  const format = (options.format || 'cedar').toLowerCase();
  const isWeaveProofFormat = format === 'weaveproof' || format === 'weaveproof-genome' || format === 'genome';
  const isOpenShellFormat = format === 'nvidia-openshell' || format === 'openshell';
  const isNemoFormat = format === 'nemo-guardrails' || format === 'nemo' || format === 'colang';

  let tools: McpToolDefinition[] = [];
  try {
    const discovered = await discoverToolsFromTarget(target, {
      demo: options.demo,
      allowExec: options.allowExec,
      demoFallbackTools: DEMO_POLICY_TOOLS,
      keepClientOpen: false,
    });
    tools = discovered.tools;
  } catch (err: any) {
    console.error(`\n❌ Error discovering tools at '${target}': ${err.message}`);
    process.exitCode = 1;
    return;
  }

  if (tools.length === 0) {
    console.error(`\n❌ Error: No tools discovered at '${target}' for policy generation.`);
    process.exitCode = 1;
    return;
  }

  const nemoBundle = isNemoFormat ? generateNemoGuardrailsBundle(tools) : null;
  const policyText =
    format === 'opa' || format === 'rego'
      ? generateOpaRegoPolicy(tools)
      : format === 'weaveproof-genome' || format === 'genome'
        ? generateWeaveProofGenomeManifest(tools)
        : format === 'weaveproof'
          ? generateWeaveProofCedarPolicy(tools)
          : isOpenShellFormat
            ? generateNvidiaOpenShellPolicy(tools)
            : isNemoFormat && nemoBundle
              ? format === 'colang'
                ? nemoBundle.colangFlows
                : nemoBundle.combinedText
              : generateCedarPolicy(tools);

  if (options.output) {
    const outPath = path.resolve(process.cwd(), options.output);
    if (isNemoFormat && nemoBundle) {
      const ext = path.extname(outPath).toLowerCase();
      if (ext === '.co') {
        fs.mkdirSync(path.dirname(outPath), { recursive: true });
        fs.writeFileSync(outPath, nemoBundle.colangFlows, 'utf-8');
        console.log(`\n✅ Exported NEMO-GUARDRAILS Colang flows to ${outPath}`);
      } else if (ext === '.yml' || ext === '.yaml') {
        const colangPath = path.join(path.dirname(outPath), 'toolveto_rails.co');
        fs.mkdirSync(path.dirname(outPath), { recursive: true });
        fs.writeFileSync(outPath, nemoBundle.configYaml, 'utf-8');
        fs.writeFileSync(colangPath, nemoBundle.colangFlows, 'utf-8');
        console.log(`\n✅ Exported NEMO-GUARDRAILS config to ${outPath} and Colang flows to ${colangPath}`);
      } else {
        const configPath = path.join(outPath, 'config.yml');
        const colangPath = path.join(outPath, 'rails', 'toolveto_rails.co');
        fs.mkdirSync(path.dirname(colangPath), { recursive: true });
        fs.writeFileSync(configPath, nemoBundle.configYaml, 'utf-8');
        fs.writeFileSync(colangPath, nemoBundle.colangFlows, 'utf-8');
        console.log(`\n✅ Exported NEMO-GUARDRAILS bundle to ${configPath} and ${colangPath}`);
      }
      console.log(
        `💡 Load in NVIDIA NeMo Guardrails / NeMo Agent Toolkit:\n` +
          `   👉 RailsConfig.from_path(${JSON.stringify(path.extname(outPath) ? path.dirname(outPath) : outPath)})\n`
      );
    } else {
      fs.mkdirSync(path.dirname(outPath), { recursive: true });
      fs.writeFileSync(outPath, policyText, 'utf-8');
      console.log(`\n✅ Exported ${format.toUpperCase()} least-privilege policy to ${outPath}`);
      if (isWeaveProofFormat) {
        console.log(
          `💡 Enterprise Upgrade: Import into WeaveProof for live @clamp ceilings, 2-of-2 SOX HITL & SOC 2/ISO 42001 audit binders:\n` +
            `   👉 weaveproof-cli policy plan --file ${path.basename(outPath)}\n`
        );
      } else if (isOpenShellFormat) {
        console.log(
          `💡 Apply directly to an NVIDIA OpenShell sandbox:\n` +
            `   👉 openshell policy set <sandbox-name> --policy ${path.basename(outPath)} --wait\n`
        );
      } else {
        console.log(
          `💡 Enforce least-privilege policies at runtime with @toolveto/shield or ToolVeto Cloud (https://toolveto.ai).\n`
        );
      }
    }
    await notifyOnboardingStep('step_3_policy_export', outPath, {
      apiUrl: options.apiUrl,
      licenseKey: options.licenseKey,
    });
  } else {
    console.log(policyText);
    await notifyOnboardingStep('step_3_policy_export', `stdout:${format}`, {
      apiUrl: options.apiUrl,
      licenseKey: options.licenseKey,
    });
  }
}
