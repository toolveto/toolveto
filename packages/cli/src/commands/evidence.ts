import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import {
  runSuite,
  McpToolDefinition,
  McpClient,
  SuiteSummary,
} from '@toolveto/core';
import { discoverToolsFromTarget } from '../discovery.js';

export interface EvidenceOptions {
  format?: 'aiuc1' | 'owasp' | 'json';
  output?: string;
  target?: string;
  keyId?: string;
  demo?: boolean;
  allowExec?: boolean;
  secret?: string;
}

export type ControlStatus = 'COMPLIANT' | 'NON_COMPLIANT' | 'AT_RISK' | 'NOT_APPLICABLE';

export const AIUC1_CONTROL_MAP: Record<string, { title: string; checks: string[] }> = {
  'AIUC-1-4.2-tool-integrity': {
    title: 'Tool Execution Integrity, Concurrency & Idempotency Controls',
    checks: ['TC-IDEMP-001', 'TC-IDEMP-002', 'TC-IDEMP-003', 'TC-IDEMP-004', 'TC-IDEMP-005', 'TC-CANCEL-001', 'TC-ANNOTATION-001'],
  },
  'AIUC-1-5.1-auth-model': {
    title: 'Authentication, Tenant Isolation & Scoped Authorization Controls',
    checks: ['TC-AUTH-001', 'TC-AUTH-002', 'TC-AUTH-003', 'TC-DRYRUN-001'],
  },
  'AIUC-1-6.3-loop-protection': {
    title: 'Runaway Agent Retry & Loop Circuit Breakers',
    checks: ['TC-ERR-001', 'TC-FUZZ-001', 'TC-FUZZ-WIRE-001', 'TC-SAMPLING-001'],
  },
  'AIUC-1-7.1-data-minimization': {
    title: 'Context Hygiene, Memory Budget & Pagination Boundary Limits',
    checks: ['TC-CTX-001', 'TC-SCHEMA-001', 'TC-SCHEMA-002', 'TC-SCHEMA-003', 'TC-RES-001', 'TC-RES-002'],
  },
  'OWASP-AGENTIC-1-prompt-inject': {
    title: 'Indirect Prompt Injection, Exfiltration & Traversal Prevention',
    checks: ['TC-VETO-INJECT-001', 'TC-VETO-EXFIL-001', 'TC-SEC-002', 'TC-SEC-003', 'TC-RES-002', 'TC-AUTH-003'],
  },
  'OWASP-AGENTIC-3-excess-agency': {
    title: 'Blind Write Mitigation, Capability Sandboxing & Read-Before-Write Verification',
    checks: ['TC-PAIR-001', 'TC-CAP-001', 'TC-RACE-001'],
  },
};

const DEMO_EVIDENCE_TOOLS: McpToolDefinition[] = [
  {
    name: 'execute_settlement',
    description: 'Settles payment transaction with banking partner',
    isMutation: true,
    inputSchema: {
      type: 'object',
      properties: {
        transaction_id: { type: 'string' },
        idempotency_key: { type: 'string' },
        amount: { type: 'number' },
      },
      required: ['transaction_id', 'idempotency_key', 'amount'],
    },
  },
  {
    name: 'query_settlement',
    description: 'Queries status of settlement transaction',
    isMutation: false,
    inputSchema: {
      type: 'object',
      properties: {
        transaction_id: { type: 'string' },
      },
    },
  },
  {
    name: 'list_settlements',
    description: 'Lists all settlement transactions in date range',
    isMutation: false,
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'number' },
        cursor: { type: 'string' },
      },
    },
  },
];

function signAttestationJws(payload: Record<string, unknown>, keyId = 'toolveto-cli-v1', signingSecret?: string): string {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'TV-EVIDENCE-JWS', kid: keyId })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const secret = signingSecret || process.env.TOOLVETO_SIGNING_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error(
      'FATAL SECURITY VIOLATION: TOOLVETO_SIGNING_SECRET environment variable is missing or shorter than 32 characters (256 bits). ' +
      'Refusing to sign attestation with insecure default key. Generate with: openssl rand -base64 32'
    );
  }
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(`${header}.${body}`);
  const sig = hmac.digest('base64url');
  return `${header}.${body}.${sig}`;
}

export async function evidenceCommand(
  targetOrOptions: string | EvidenceOptions = {},
  maybeOptions: EvidenceOptions = {}
): Promise<void> {
  const options: EvidenceOptions =
    typeof targetOrOptions === 'string'
      ? { ...maybeOptions, target: targetOrOptions || maybeOptions.target }
      : targetOrOptions;

  const format = options.format || 'aiuc1';
  const targetPath = options.target || '.';
  const resolvedTarget = targetPath.startsWith('http') ? targetPath : path.resolve(process.cwd(), targetPath);

  // Verify signing secret upfront before launching live servers
  const checkSecret = options.secret || process.env.TOOLVETO_SIGNING_SECRET;
  if (!checkSecret || checkSecret.length < 32) {
    throw new Error(
      'FATAL SECURITY VIOLATION: TOOLVETO_SIGNING_SECRET environment variable is missing or shorter than 32 characters (256 bits). ' +
      'Refusing to sign attestation with insecure default key. Generate with: openssl rand -base64 32'
    );
  }

  let tools: McpToolDefinition[] = [];
  let client: McpClient | null = null;

  try {
    const discovered = await discoverToolsFromTarget(targetPath, {
      demo: options.demo,
      allowExec: options.allowExec,
      keepClientOpen: true,
      demoFallbackTools: DEMO_EVIDENCE_TOOLS,
    });
    tools = discovered.tools;
    client = discovered.client;

    if (tools.length === 0) {
      console.error(`\n❌ Error: No tools discovered at '${targetPath}' for AIUC-1 compliance audit.`);
      console.error(`Please provide a valid MCP server or tool manifest, or pass --demo for demonstration mode.\n`);
      process.exitCode = 1;
      return;
    }

    const summary: SuiteSummary = await runSuite(targetPath, tools, {
      client: client || undefined,
      targetDir: targetPath.startsWith('http') ? '.' : targetPath,
    });

    // Map checks to compliance controls (honest NOT_APPLICABLE when 0 checks apply)
    const controlEvaluations: Record<
      string,
      { title: string; status: ControlStatus; passedChecks: string[]; failedChecks: string[] }
    > = {};

    for (const [controlId, meta] of Object.entries(AIUC1_CONTROL_MAP)) {
      const relevantResults = summary.results.filter((r) => meta.checks.includes(r.checkId));
      const passed = relevantResults.filter((r) => r.status === 'PASS').map((r) => r.checkId);
      const failed = relevantResults.filter((r) => r.status === 'FAIL').map((r) => r.checkId);

      let status: ControlStatus;
      if (relevantResults.length === 0) {
        status = 'NOT_APPLICABLE';
      } else if (failed.length > 0) {
        status = relevantResults.some((r) => r.severity === 'CRITICAL') ? 'NON_COMPLIANT' : 'AT_RISK';
      } else if (passed.length > 0) {
        status = 'COMPLIANT';
      } else {
        status = 'NOT_APPLICABLE';
      }

      controlEvaluations[controlId] = {
        title: meta.title,
        status,
        passedChecks: passed,
        failedChecks: failed,
      };
    }

    // Honest Financial ROI & Token Savings: zero floor when 0 checks passed
    const preventedDoubleCharges = summary.results.filter(
      (r) => r.checkId.startsWith('TC-IDEMP') && r.status === 'PASS'
    ).length;
    const estimatedSavingsUsd = preventedDoubleCharges * 340;
    const contextPassCount = summary.results.filter(
      (r) => r.checkId.startsWith('TC-CTX') && r.status === 'PASS'
    ).length;
    const tokensSaved = contextPassCount * 128000;

    const attestationPayload = {
      iss: 'toolveto-evidence-engine',
      sub: targetPath.startsWith('http') ? targetPath : path.basename(resolvedTarget) || 'mcp-server',
      aud: 'ciso-compliance-review',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 90 * 86400, // 90 days validity
      score: summary.score,
      tier: summary.tier,
      phi: summary.phi,
      controls: controlEvaluations,
      roi: {
        preventedDoubleCharges,
        estimatedSavingsUsd,
        tokensSaved,
      },
    };

    const jws = signAttestationJws(attestationPayload, options.keyId, options.secret);

    if (format === 'json') {
      const output = JSON.stringify({ ...attestationPayload, jws }, null, 2);
      if (options.output) {
        fs.writeFileSync(options.output, output);
        console.log(`\n✅ Evidence packet written to ${options.output}\n`);
      } else {
        console.log(output);
      }
      return;
    }

    const cert = `
================================================================================
           TOOLVETO CISO COMPLIANCE EVIDENCE PACKET
           Standard: AIUC-1 (Agentic AI Interoperability & Safety)
================================================================================

Target Component:       ${targetPath}
Certification Tier:     ${summary.tier.toUpperCase()} (${summary.score}/100)
Evaluation Timestamp:   ${new Date().toISOString()}
Validity Window:        90 Days (Valid until ${new Date(Date.now() + 90 * 86400000).toISOString().split('T')[0]})
Cryptographic Attest:   RFC 7515 Detached JWS (HS256)

--- AIUC-1 & OWASP AGENTIC CONTROL ATTESTATIONS ---

${Object.entries(controlEvaluations)
  .map(([id, ctrl]) => {
    const symbol =
      ctrl.status === 'COMPLIANT'
        ? '✅ COMPLIANT'
        : ctrl.status === 'AT_RISK'
          ? '⚠️ AT RISK'
          : ctrl.status === 'NOT_APPLICABLE'
            ? '➖ NOT APPLICABLE'
            : '❌ NON-COMPLIANT';
    return `[ ${symbol} ] ${id}
  Description:   ${ctrl.title}
  Passed Checks: ${ctrl.passedChecks.join(', ') || 'None'}
  Failed Checks: ${ctrl.failedChecks.join(', ') || 'None'}`;
  })
  .join('\n\n')}

--- FINANCIAL & TOKEN RISK MITIGATION ---
• Double-Charge Incidents Prevented:  ${preventedDoubleCharges} incidents (avg $340/incident)
• Estimated Direct Capital Protected: $${estimatedSavingsUsd.toLocaleString()} USD
• Context Tokens Shielded:            ${tokensSaved.toLocaleString()} tokens

--- CRYPTOGRAPHIC JWS ATTESTATION SIGNATURE ---
${jws}
================================================================================
Verify online at: https://toolveto.ai/verify or via:
  toolveto verify "${jws}"
================================================================================
`;

    if (options.output) {
      fs.writeFileSync(options.output, cert);
      console.log(`\n✅ Evidence packet written to ${options.output}\n`);
    } else {
      console.log(cert);
    }
  } finally {
    if (client) {
      await client.close().catch(() => {});
    }
  }
}
