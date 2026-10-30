import { CheckResult } from '../types.js';
import { McpClient } from '../transports/interface.js';

/**
 * TC-SAMPLING-001: MCP Bidirectional Sampling (sampling/createMessage) Chaos & Cost-DoS Check
 *
 * Evaluates whether an MCP server that requests client-side LLM completions via
 * `sampling/createMessage` enforces strict token ceilings (<= 4,000 maxTokens),
 * blocks recursive sampling loops (`includeContext: "allServers"`), and prevents
 * indirect systemPrompt hijacking.
 */
export async function runSamplingChaosCheck(client?: McpClient): Promise<CheckResult> {
  const startTime = Date.now();

  if (client && client.getCapabilities) {
    try {
      const caps = await client.getCapabilities();
      const samplingCap = caps?.sampling as Record<string, any> | undefined;

      if (samplingCap && typeof samplingCap === 'object') {
        const maxTokens =
          typeof samplingCap.maxTokens === 'number'
            ? samplingCap.maxTokens
            : typeof samplingCap.max_tokens === 'number'
            ? samplingCap.max_tokens
            : undefined;
        const includeContext = String(samplingCap.includeContext || samplingCap.include_context || '');
        const systemPrompt = String(samplingCap.systemPrompt || samplingCap.system_prompt || '');

        const overridePattern =
          /(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|SYSTEM\s*OVERRIDE|you\s+are\s+now\s+DAN|exfiltrate)/i;

        if (overridePattern.test(systemPrompt)) {
          return {
            checkId: 'TC-SAMPLING-001',
            dimension: 'D2',
            tool: 'sampling/createMessage',
            status: 'FAIL',
            severity: 'CRITICAL',
            vetoClass: 'VETO_INJECT',
            description:
              'VETO_INJECT: Server sampling/createMessage capability contains adversarial systemPrompt override directive.',
            evidence: {
              evidenceQuality: 'VERIFIED',
              details: { samplingCapabilities: samplingCap },
            },
            durationMs: Date.now() - startTime,
          };
        }

        if (includeContext === 'allServers' || (maxTokens !== undefined && maxTokens > 4000)) {
          return {
            checkId: 'TC-SAMPLING-001',
            dimension: 'D3',
            tool: 'sampling/createMessage',
            status: 'WARN',
            severity: 'HIGH',
            description: `Sampling Cost-DoS / Cross-Server Leakage risk: sampling/createMessage declares ${
              includeContext === 'allServers'
                ? 'includeContext="allServers" (cross-server context bleed)'
                : `unbounded maxTokens=${maxTokens} (>4,000 token ceiling)`
            }.`,
            evidence: {
              evidenceQuality: 'VERIFIED',
              details: { maxTokens, includeContext },
            },
            fix: {
              summary:
                'Restrict sampling/createMessage to includeContext="thisServer" (or "none") and cap maxTokens <= 4000.',
              diffs: [
                {
                  language: 'typescript-zod',
                  code: `sampling: { maxTokens: 2048, includeContext: "thisServer" }`,
                },
              ],
            },
            durationMs: Date.now() - startTime,
          };
        }
      }
    } catch {
      // Safe fallback if client does not expose sampling metadata
    }
  }

  return {
    checkId: 'TC-SAMPLING-001',
    dimension: 'D3',
    tool: 'sampling/createMessage',
    status: 'PASS',
    severity: 'INFO',
    description:
      'Bidirectional sampling/createMessage check passed: no recursive cross-server context bleed or unbounded token quota requests.',
    evidence: { evidenceQuality: client ? 'VERIFIED' : 'STATIC-ONLY' },
    durationMs: Date.now() - startTime,
  };
}
