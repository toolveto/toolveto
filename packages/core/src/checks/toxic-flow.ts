import { CheckResult, McpToolDefinition } from '../types.js';

export type CapabilityAxis =
  | 'PRIVATE_DATA_SOURCE'
  | 'UNTRUSTED_INGEST'
  | 'EXTERNAL_EGRESS_OR_MUTATION';

export interface ClassifiedToolNode {
  serverName: string;
  toolName: string;
  qualifiedName: string;
  axes: CapabilityAxis[];
  reasons: string[];
}

export interface ToxicFlowPath {
  ingestNode: ClassifiedToolNode;
  privateDataNode: ClassifiedToolNode;
  egressNode: ClassifiedToolNode;
  crossServer: boolean;
  chainLabel: string;
}

export interface ToxicFlowAnalysis {
  nodes: ClassifiedToolNode[];
  untrustedIngestTools: ClassifiedToolNode[];
  privateDataTools: ClassifiedToolNode[];
  externalEgressTools: ClassifiedToolNode[];
  toxicPaths: ToxicFlowPath[];
  lethalTrifectaDetected: boolean;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

const UNTRUSTED_INGEST_RE =
  /\b(fetch_url|fetch_page|web_fetch|crawl|scrape|browse|browser_navigate|http_get|get_issue|list_issues|get_pull_request|read_email|incoming_email|receive_webhook|search_web|web_search|brave_search|read_page|rss_feed)\b/i;

const PRIVATE_DATA_RE =
  /\b(execute_sql|run_sql|query_sql|query_customer_sql|postgres|mysql|sqlite|supabase|neon|mongo|redis|read_file|list_dir|filesystem_read|get_secret|read_vault|get_env|read_crm|list_customers|get_customer|slack_read|get_channel_history|read_dm|gdrive_read|s3_get)\b/i;

const EXTERNAL_EGRESS_RE =
  /\b(send_email|send_message|slack_post_message|post_message|post_comment|create_comment|publish_|notify_|send_webhook|http_post|http_request|transfer_funds|payout|upload_external|dispatch_webhook)\b/i;

export function classifyToolCapabilities(
  tool: McpToolDefinition & { serverName?: string }
): ClassifiedToolNode {
  const serverName = tool.serverName || 'default';
  const qualifiedName = tool.serverName ? `${tool.serverName}::${tool.name}` : tool.name;
  const nameAndServer = `${serverName} ${tool.name}`;
  const text = `${nameAndServer} ${tool.description || ''}`;

  const axes = new Set<CapabilityAxis>();
  const reasons: string[] = [];

  const openWorld = tool.openWorldHint === true || tool.annotations?.openWorldHint === true;
  const readOnly = tool.readOnlyHint === true || tool.annotations?.readOnlyHint === true || tool.isMutation === false;
  const destructive = tool.destructiveHint === true || tool.annotations?.destructiveHint === true;

  if (readOnly && (UNTRUSTED_INGEST_RE.test(text) || openWorld)) {
    axes.add('UNTRUSTED_INGEST');
    reasons.push(openWorld ? 'openWorldHint+readOnly ingest' : 'matches untrusted external ingest pattern');
  }

  if (readOnly && PRIVATE_DATA_RE.test(text)) {
    axes.add('PRIVATE_DATA_SOURCE');
    reasons.push('accesses private data / internal store');
  }

  if (!readOnly && (EXTERNAL_EGRESS_RE.test(text) || openWorld || destructive)) {
    axes.add('EXTERNAL_EGRESS_OR_MUTATION');
    reasons.push(
      destructive
        ? 'destructive external/state mutation'
        : openWorld
          ? 'openWorldHint mutation/egress'
          : 'matches outbound egress or external mutation sink'
    );
  }

  return {
    serverName,
    toolName: tool.name,
    qualifiedName,
    axes: Array.from(axes),
    reasons,
  };
}

export function analyzeToxicFlow(
  tools: Array<McpToolDefinition & { serverName?: string }>
): ToxicFlowAnalysis {
  const nodes = tools.map(classifyToolCapabilities);
  const untrustedIngestTools = nodes.filter((n) => n.axes.includes('UNTRUSTED_INGEST'));
  const privateDataTools = nodes.filter((n) => n.axes.includes('PRIVATE_DATA_SOURCE'));
  const externalEgressTools = nodes.filter((n) => n.axes.includes('EXTERNAL_EGRESS_OR_MUTATION'));

  const toxicPaths: ToxicFlowPath[] = [];
  for (const ingest of untrustedIngestTools) {
    for (const priv of privateDataTools) {
      if (priv.qualifiedName === ingest.qualifiedName) continue;
      for (const egress of externalEgressTools) {
        if (egress.qualifiedName === ingest.qualifiedName || egress.qualifiedName === priv.qualifiedName) continue;
        const distinctServers = new Set([ingest.serverName, priv.serverName, egress.serverName]);
        toxicPaths.push({
          ingestNode: ingest,
          privateDataNode: priv,
          egressNode: egress,
          crossServer: distinctServers.size > 1,
          chainLabel: `${ingest.qualifiedName} -> [Shared LLM Context] -> ${priv.qualifiedName} -> ${egress.qualifiedName}`,
        });
        if (toxicPaths.length >= 25) break;
      }
      if (toxicPaths.length >= 25) break;
    }
    if (toxicPaths.length >= 25) break;
  }

  const lethalTrifectaDetected = toxicPaths.length > 0;
  const activeAxesCount =
    (untrustedIngestTools.length > 0 ? 1 : 0) +
    (privateDataTools.length > 0 ? 1 : 0) +
    (externalEgressTools.length > 0 ? 1 : 0);

  const riskLevel: ToxicFlowAnalysis['riskLevel'] = lethalTrifectaDetected
    ? 'CRITICAL'
    : activeAxesCount === 2
      ? 'HIGH'
      : activeAxesCount === 1
        ? 'MEDIUM'
        : 'LOW';

  return {
    nodes,
    untrustedIngestTools,
    privateDataTools,
    externalEgressTools,
    toxicPaths,
    lethalTrifectaDetected,
    riskLevel,
  };
}

export function runToxicFlowCheck(
  tools: Array<McpToolDefinition & { serverName?: string }>,
  options: { hasRuntimeTaintBoundary?: boolean } = {}
): CheckResult {
  const startTime = Date.now();
  const analysis = analyzeToxicFlow(tools);

  if (analysis.lethalTrifectaDetected && !options.hasRuntimeTaintBoundary) {
    const primary = analysis.toxicPaths[0]!;
    return {
      checkId: 'TC-TOXIC-001',
      dimension: 'D5',
      tool: primary.egressNode.qualifiedName,
      status: 'FAIL',
      severity: 'CRITICAL',
      vetoClass: 'VETO_EXFIL',
      description: `Lethal Trifecta exfiltration chain detected (${analysis.toxicPaths.length} path(s)): ${primary.chainLabel} without runtime taint boundary`,
      evidence: {
        evidenceQuality: 'STATIC-ONLY',
        details: {
          riskLevel: analysis.riskLevel,
          pathCount: analysis.toxicPaths.length,
          crossServerPaths: analysis.toxicPaths.filter((p) => p.crossServer).length,
          samplePaths: analysis.toxicPaths.slice(0, 5).map((p) => p.chainLabel),
          untrustedIngestTools: analysis.untrustedIngestTools.map((n) => n.qualifiedName),
          privateDataTools: analysis.privateDataTools.map((n) => n.qualifiedName),
          externalEgressTools: analysis.externalEgressTools.map((n) => n.qualifiedName),
        },
      },
      fix: {
        summary: 'Export WeaveProof taint-boundary Cedar policy (@taint_source + !context.session_taint.contains)',
        applyCommand: 'npx toolveto export-policy . --format weaveproof --output weaveproof.cedar',
        diffs: [
          {
            language: 'typescript-zod',
            code:
              `+ // WeaveProof Taint Boundary (blocks Lethal Trifecta exfiltration at runtime):\n` +
              `+ @taint_source("UNTRUSTED_EXTERNAL_INGEST")\n` +
              `+ tool "${primary.ingestNode.qualifiedName}";\n` +
              `+ forbid (principal, action == Action::"tools/call", resource == Tool::"${primary.egressNode.qualifiedName}")\n` +
              `+ when { context.session_taint.contains("UNTRUSTED_EXTERNAL_INGEST") };`,
          },
        ],
      },
      durationMs: Date.now() - startTime,
    };
  }

  return {
    checkId: 'TC-TOXIC-001',
    dimension: 'D5',
    tool: 'workspace',
    status: 'PASS',
    severity: 'LOW',
    description: analysis.lethalTrifectaDetected
      ? 'Lethal Trifecta paths protected by explicit runtime taint boundary'
      : `No 3-axis Lethal Trifecta exfiltration chain detected (risk: ${analysis.riskLevel})`,
    evidence: {
      evidenceQuality: 'STATIC-ONLY',
      details: {
        riskLevel: analysis.riskLevel,
        untrustedIngestCount: analysis.untrustedIngestTools.length,
        privateDataCount: analysis.privateDataTools.length,
        externalEgressCount: analysis.externalEgressTools.length,
      },
    },
    durationMs: Date.now() - startTime,
  };
}
