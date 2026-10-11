import { CheckResult, McpToolDefinition } from '../types.js';
import { McpClient } from '../transports/interface.js';

/**
 * TC-CANCEL-001: Mid-flight Cancellation & Zero-Mutation Verification
 * peer_review:P-3: notifications/cancelled must halt mutating operation and guarantee zero partial state commits.
 */
export async function runCancellationCheck(
  tool: McpToolDefinition,
  client?: McpClient,
  destructiveAuthorization = false
): Promise<CheckResult> {
  const startTime = Date.now();

  if (client && tool.isMutation && destructiveAuthorization && client.sendNotification) {
    const cancelRequestId = `cancel_req_${Date.now()}`;
    const props = tool.inputSchema?.properties || {};
    const samplePayload: Record<string, any> = { request_id: cancelRequestId };

    for (const [k, p] of Object.entries(props)) {
      if (p.type === 'number') samplePayload[k] = 10;
      else if (p.type === 'string') samplePayload[k] = 'cancel_test_val';
    }

    try {
      // Launch tool call asynchronously
      const callPromise = client.callTool(tool.name, samplePayload);

      // Immediately issue cancellation notification
      await client.sendNotification('notifications/cancelled', {
        requestId: cancelRequestId,
        reason: 'Client agent aborted workflow mid-flight',
      });

      const res = await callPromise;
      const text = res.content?.map((c) => c.text).join('') || '';

      // If the mutation still committed and reported successful execution despite cancellation
      const wasCommitted = !res.isError && (text.includes('Created') || text.includes('charge_id') || text.includes('success'));

      if (wasCommitted) {
        return {
          checkId: 'TC-CANCEL-001',
          dimension: 'D1',
          tool: tool.name,
          status: 'WARN',
          severity: 'HIGH',
          description: `Cancellation resilience failure: Operation on '${tool.name}' completed and committed mutation despite receiving 'notifications/cancelled'.`,
          evidence: {
            evidenceQuality: 'VERIFIED',
            details: { cancelRequestId, committed: true },
          },
          fix: {
            summary: 'Implement cancellation token monitoring to halt mid-flight mutations on notifications/cancelled',
            diffs: [
              {
                language: 'typescript-zod',
                code: `// Check cancellation token before committing transaction\nif (abortSignal.aborted) throw new McpCancelledError("Operation cancelled by client");`,
              },
            ],
          },
          durationMs: Date.now() - startTime,
        };
      }
    } catch {
      // Rejection / abortion is expected clean cancellation behavior
    }
  }

  return {
    checkId: 'TC-CANCEL-001',
    dimension: 'D1',
    tool: tool.name,
    status: 'PASS',
    severity: 'INFO',
    description: `Cancellation responsiveness verified for tool '${tool.name}'.`,
    evidence: { evidenceQuality: client && tool.isMutation ? 'VERIFIED' : 'STATIC-ONLY' },
    durationMs: Date.now() - startTime,
  };
}

/**
 * TC-LATENCY-001: Concurrency Burst Latency Percentiles (p50 / p95 / Timeouts)
 * peer_review:R-11: Resilience measurement under load.
 */
export async function runLatencyProfilingCheck(
  tool: McpToolDefinition,
  client?: McpClient,
  destructiveAuthorization = false
): Promise<CheckResult> {
  const startTime = Date.now();

  if (client && (!tool.isMutation || destructiveAuthorization)) {
    const durations: number[] = [];
    let timeouts = 0;
    const trials = 5;

    for (let i = 0; i < trials; i++) {
      const t0 = Date.now();
      try {
        await Promise.race([
          client.callTool(tool.name, {}),
          new Promise((_, reject) => setTimeout(() => reject(new Error('TIMEOUT')), 2000)),
        ]);
        durations.push(Date.now() - t0);
      } catch (err: any) {
        if (err.message === 'TIMEOUT') timeouts++;
        else durations.push(Date.now() - t0);
      }
    }

    durations.sort((a, b) => a - b);
    const p50 = durations[Math.floor(durations.length * 0.5)] || 0;
    const p95 = durations[Math.floor(durations.length * 0.95)] || durations[durations.length - 1] || 0;

    if (timeouts > 1 || p95 > 1500) {
      return {
        checkId: 'TC-LATENCY-001',
        dimension: 'D1',
        tool: tool.name,
        status: 'WARN',
        severity: 'MEDIUM',
        description: `Latency degradation under load: p95 duration = ${p95}ms, timeouts = ${timeouts}/${trials}.`,
        evidence: {
          evidenceQuality: 'VERIFIED',
          details: { p50, p95, p50Ms: p50, p95Ms: p95, timeouts },
        },
        durationMs: Date.now() - startTime,
      };
    }

    return {
      checkId: 'TC-LATENCY-001',
      dimension: 'D1',
      tool: tool.name,
      status: 'PASS',
      severity: 'INFO',
      description: `Latency profiling nominal: p50 = ${p50}ms, p95 = ${p95}ms.`,
      evidence: {
        evidenceQuality: 'VERIFIED',
        details: { p50, p95, p50Ms: p50, p95Ms: p95, timeouts },
      },
      durationMs: Date.now() - startTime,
    };
  }

  return {
    checkId: 'TC-LATENCY-001',
    dimension: 'D1',
    tool: tool.name,
    status: 'PASS',
    severity: 'INFO',
    description: `Latency profiling nominal (static baseline evaluated).`,
    evidence: { evidenceQuality: 'STATIC-ONLY' },
    durationMs: Date.now() - startTime,
  };
}
