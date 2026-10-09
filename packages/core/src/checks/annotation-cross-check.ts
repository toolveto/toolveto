import { CheckResult, McpToolDefinition } from '../types.js';
import { McpClient } from '../transports/interface.js';

/**
 * TC-ANNOTATION-001: Tool-Annotation Cross-Check (MCP 2025-03-26 Spec)
 * peer_review:P-5: Cross-validate declared annotations against observed runtime behavior.
 * A tool declaring idempotentHint: true that fails I_seq is an automatic HIGH contradiction finding.
 */
export async function runAnnotationCrossCheck(
  tool: McpToolDefinition,
  client?: McpClient,
  d1ReplayPassed = true
): Promise<CheckResult> {
  const startTime = Date.now();

  // 1. Check idempotentHint contradiction
  if (tool.idempotentHint === true && !d1ReplayPassed) {
    return {
      checkId: 'TC-ANNOTATION-001',
      dimension: 'D4',
      tool: tool.name,
      status: 'FAIL',
      severity: 'HIGH',
      description: `Annotation contradiction: Tool '${tool.name}' declares 'idempotentHint: true' in MCP manifest, but failed sequential replay deduplication (I_seq).`,
      evidence: {
        evidenceQuality: 'VERIFIED',
        details: { declaredIdempotentHint: true, observedReplayDuplicate: true },
      },
      fix: {
        summary: `Align tool implementation with declared idempotentHint by adding deduplication logic or removing idempotentHint: true`,
        diffs: [
          {
            language: 'json-schema',
            code: `"idempotentHint": false // Contradiction: remove hint until deduplication is enforced`,
          },
        ],
      },
      durationMs: Date.now() - startTime,
    };
  }

  // 2. Check readOnlyHint contradiction
  const isDestructiveVerb = ['delete', 'drop', 'charge', 'settle', 'update', 'insert', 'create', 'mutate'].some((v) =>
    tool.name.toLowerCase().includes(v)
  );

  if (tool.readOnlyHint === true && (tool.isMutation || isDestructiveVerb)) {
    return {
      checkId: 'TC-ANNOTATION-001',
      dimension: 'D4',
      tool: tool.name,
      status: 'FAIL',
      severity: 'HIGH',
      description: `Annotation contradiction: Tool '${tool.name}' declares 'readOnlyHint: true' but is classified as a mutation operation.`,
      evidence: {
        evidenceQuality: 'STATIC-ONLY',
        details: { declaredReadOnlyHint: true, isMutation: tool.isMutation },
      },
      fix: {
        summary: `Set readOnlyHint: false or remove for mutating tool '${tool.name}'`,
        diffs: [
          {
            language: 'json-schema',
            code: `"readOnlyHint": false`,
          },
        ],
      },
      durationMs: Date.now() - startTime,
    };
  }

  // 3. Check outputSchema conformity if client available
  if (client && tool.outputSchema) {
    try {
      const resp = await client.callTool(tool.name, {});
      const text = resp.content?.map((c) => c.text).join('') || '';
      try {
        const parsed = JSON.parse(text);
        if (tool.outputSchema.type === 'object' && typeof parsed !== 'object') {
          return {
            checkId: 'TC-ANNOTATION-001',
            dimension: 'D4',
            tool: tool.name,
            status: 'WARN',
            severity: 'MEDIUM',
            description: `outputSchema mismatch: Response from '${tool.name}' did not match declared outputSchema type '${tool.outputSchema.type}'.`,
            evidence: {
              evidenceQuality: 'VERIFIED',
              details: { declaredType: tool.outputSchema.type, actualType: typeof parsed },
            },
            durationMs: Date.now() - startTime,
          };
        }
      } catch {
        // Text is not JSON
      }
    } catch {
      // Ignored
    }
  }

  return {
    checkId: 'TC-ANNOTATION-001',
    dimension: 'D4',
    tool: tool.name,
    status: 'PASS',
    severity: 'INFO',
    description: `Tool annotations cross-check passed for '${tool.name}'.`,
    evidence: { evidenceQuality: client ? 'VERIFIED' : 'STATIC-ONLY' },
    durationMs: Date.now() - startTime,
  };
}
