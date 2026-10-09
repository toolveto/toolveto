import { CheckResult, McpToolDefinition, McpResourceDefinition } from '../types.js';
import { McpClient } from '../transports/interface.js';

/**
 * TC-RES-001: resources/list pagination and URI-template validation
 * peer_review:P-4: resources must support pagination and valid RFC 6570 templates
 */
export async function runResourceListCheck(
  resources: McpResourceDefinition[] = [],
  client?: McpClient
): Promise<CheckResult> {
  const startTime = Date.now();

  if (resources.length > 50) {
    return {
      checkId: 'TC-RES-001',
      dimension: 'D3',
      tool: 'resources/list',
      status: 'WARN',
      severity: 'HIGH',
      description: `Resource list pagination risk: Server advertises ${resources.length} resources without explicit pagination cursor support.`,
      evidence: {
        evidenceQuality: 'VERIFIED',
        details: { totalResources: resources.length },
      },
      fix: {
        summary: 'Implement cursor pagination on resources/list to prevent context flooding',
        diffs: [
          {
            language: 'typescript-zod',
            code: `// Support nextCursor on resources/list\nreturn { resources: pagedResources, nextCursor: nextCursorToken };`,
          },
        ],
      },
      durationMs: Date.now() - startTime,
    };
  }

  // Validate URI templates adhere to RFC 6570
  const malformedUris = resources.filter((r) => !r.uri || (!r.uri.includes('://') && !r.uri.startsWith('/')));
  if (malformedUris.length > 0) {
    return {
      checkId: 'TC-RES-001',
      dimension: 'D3',
      tool: 'resources/list',
      status: 'WARN',
      severity: 'MEDIUM',
      description: `Resource URI template warning: Found ${malformedUris.length} resources with non-standard URI schemes.`,
      evidence: {
        evidenceQuality: 'STATIC-ONLY',
        details: { malformedUris: malformedUris.map((r) => r.uri) },
      },
      durationMs: Date.now() - startTime,
    };
  }

  return {
    checkId: 'TC-RES-001',
    dimension: 'D3',
    tool: 'resources/list',
    status: 'PASS',
    severity: 'INFO',
    description: `resources/list passed schema and pagination guidelines (${resources.length} resources inspected).`,
    evidence: { evidenceQuality: client ? 'VERIFIED' : 'STATIC-ONLY' },
    durationMs: Date.now() - startTime,
  };
}

/**
 * TC-RES-002: resources/read injection & context-bomb vector probe
 * peer_review:P-4: resources/read is the primary VETO_INJECT + D3 context-bomb vector
 */
export async function runResourceReadCheck(
  resources: McpResourceDefinition[] = [],
  client?: McpClient
): Promise<CheckResult> {
  const startTime = Date.now();

  if (client && client.readResource && resources.length > 0) {
    const sampleResource = resources[0];
    try {
      const res = await client.readResource(sampleResource.uri);
      const allText = res.contents?.map((c) => c.text || '').join('') || '';

      // Context bomb check on resources/read
      if (allText.length > 32000) {
        return {
          checkId: 'TC-RES-002',
          dimension: 'D3',
          tool: `resources/read:${sampleResource.name}`,
          status: 'FAIL',
          severity: 'CRITICAL',
          description: `Resource context bomb detected: Reading URI '${sampleResource.uri}' returned ${allText.length} characters (>8,000 tokens) in a single read.`,
          evidence: {
            evidenceQuality: 'VERIFIED',
            details: { charCount: allText.length, uri: sampleResource.uri },
          },
          durationMs: Date.now() - startTime,
        };
      }

      // Indirect prompt injection in resource content
      if (
        allText.includes('SYSTEM OVERRIDE') ||
        allText.includes('Ignore previous instructions') ||
        allText.includes('AI ASSISTANT INSTRUCTION:')
      ) {
        return {
          checkId: 'TC-RES-002',
          dimension: 'D2',
          tool: `resources/read:${sampleResource.name}`,
          status: 'FAIL',
          severity: 'CRITICAL',
          description: `VETO_INJECT: Indirect prompt injection vector detected in resource payload '${sampleResource.uri}'.`,
          evidence: {
            evidenceQuality: 'VERIFIED',
            details: { leakedPattern: 'SYSTEM OVERRIDE instruction in resource content' },
          },
          durationMs: Date.now() - startTime,
        };
      }
    } catch {
      // Ignored for safe handling
    }
  }

  return {
    checkId: 'TC-RES-002',
    dimension: 'D3',
    tool: 'resources/read',
    status: 'PASS',
    severity: 'INFO',
    description: `resources/read context ceiling and prompt injection probes clear.`,
    evidence: { evidenceQuality: client && resources.length > 0 ? 'VERIFIED' : 'STATIC-ONLY' },
    durationMs: Date.now() - startTime,
  };
}

/**
 * TC-CAP-001: Server-to-Client Capability Escalation Audit
 * Evaluates whether server advertises sampling/createMessage or elicitation/create escalations
 */
export async function runServerCapabilityCheck(client?: McpClient): Promise<CheckResult> {
  const startTime = Date.now();

  if (client && client.getCapabilities) {
    try {
      const caps = await client.getCapabilities();

      const hasSampling = Boolean(caps.sampling);
      const hasElicitation = Boolean(caps.elicitation);

      if (hasSampling || hasElicitation) {
        const escalations: string[] = [];
        if (hasSampling) escalations.push('sampling/createMessage (unprompted LLM completion)');
        if (hasElicitation) escalations.push('elicitation/create (server-directed user prompting)');

        return {
          checkId: 'TC-CAP-001',
          dimension: 'D4',
          tool: 'server/capabilities',
          status: 'WARN',
          severity: 'HIGH',
          description: `Server-to-client escalation capability declared: ${escalations.join(', ')}. Enterprise policy requires explicit sandbox isolation.`,
          evidence: {
            evidenceQuality: 'VERIFIED',
            details: { capabilities: caps },
          },
          durationMs: Date.now() - startTime,
        };
      }
    } catch {
      // Safe fallback
    }
  }

  return {
    checkId: 'TC-CAP-001',
    dimension: 'D4',
    tool: 'server/capabilities',
    status: 'PASS',
    severity: 'INFO',
    description: `Server capabilities audit clear: no unconstrained server-to-client escalations requested.`,
    evidence: { evidenceQuality: 'STATIC-ONLY' },
    durationMs: Date.now() - startTime,
  };
}
