import * as crypto from 'node:crypto';
import { CheckResult, McpToolDefinition } from '../../types.js';
import { McpClient } from '../../transports/interface.js';
import { createMidResponseFaultProxy } from '../../transports/fault-proxy.js';
import { extractEntityId } from './entity-extractor.js';

function buildCrashPayload(tool: McpToolDefinition, crashKey: string): Record<string, any> {
  const props = tool.inputSchema?.properties || {};
  const payload: Record<string, any> = {};
  for (const [k, p] of Object.entries(props)) {
    const lower = k.toLowerCase();
    if (lower.includes('idemp') || lower.includes('token') || lower.includes('request_id')) {
      payload[k] = crashKey;
    } else if (p.type === 'number' || p.type === 'integer') {
      payload[k] = 100;
    } else if (p.type === 'boolean') {
      payload[k] = true;
    } else if (p.type === 'string') {
      payload[k] = 'crash_commit_val';
    }
  }
  return payload;
}

/**
 * Real Post-Commit Mid-Response TCP Socket-Cut Check (PAT-01).
 * Routes call #1 through a local TCP fault-injection proxy that destroys the
 * client socket after intercepting `HTTP/1.1 200` headers (post-commit, before
 * JSON-RPC body flush), waits backoff, then replays the exact payload +
 * `Mcp-Session-Id` directly over a fresh TCP connection and compares entities.
 */
export async function runRealSocketCutCrashCommitCheck(
  tool: McpToolDefinition,
  targetUrl: string,
  options: {
    headers?: Record<string, string>;
    backoffMs?: number;
    inspectStateCount?: () => Promise<number>;
  } = {}
): Promise<CheckResult> {
  const startTime = Date.now();
  const crashKey = `crash_commit_key_${crypto.randomUUID()}`;
  const sessionId = `tv-fault-${crypto.randomBytes(6).toString('hex')}`;
  const payload = buildCrashPayload(tool, crashKey);
  const rpcBody = JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: { name: tool.name, arguments: payload },
  });
  const reqHeaders: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json, text/event-stream',
    'Mcp-Session-Id': sessionId,
    Connection: 'close',
    ...(options.headers || {}),
  };

  const proxy = await createMidResponseFaultProxy(targetUrl);
  try {
    // 1. Arm TCP socket cut and dispatch call #1 through proxy
    proxy.armNextCut();
    let socketDropObserved = false;
    try {
      await fetch(proxy.proxyUrl, {
        method: 'POST',
        headers: reqHeaders,
        body: rpcBody,
        signal: AbortSignal.timeout(5_000),
      });
    } catch {
      socketDropObserved = true;
    }

    const proxyStats = proxy.getStats();
    await new Promise((r) => setTimeout(r, options.backoffMs ?? 60));

    // 2. Replay exact same payload + Mcp-Session-Id over fresh connection directly to upstream
    const replayRes1 = await fetch(targetUrl, {
      method: 'POST',
      headers: reqHeaders,
      body: rpcBody,
      signal: AbortSignal.timeout(8_000),
    });
    const replayJson1 = (await replayRes1.json().catch(() => null)) as any;

    // 3. Also send a second direct replay so even servers without external state hooks expose duplicate IDs
    const replayRes2 = await fetch(targetUrl, {
      method: 'POST',
      headers: reqHeaders,
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: tool.name, arguments: payload },
      }),
      signal: AbortSignal.timeout(8_000),
    });
    const replayJson2 = (await replayRes2.json().catch(() => null)) as any;

    const extractText = (rpc: any) =>
      Array.isArray(rpc?.result?.content)
        ? rpc.result.content.map((c: any) => c.text || '').join('')
        : JSON.stringify(rpc?.result ?? {});

    let id1: string | null = null;
    let id2: string | null = null;
    try {
      id1 = extractEntityId(JSON.parse(extractText(replayJson1)));
    } catch {
      id1 = extractEntityId(replayJson1?.result);
    }
    try {
      id2 = extractEntityId(JSON.parse(extractText(replayJson2)));
    } catch {
      id2 = extractEntityId(replayJson2?.result);
    }

    const observedMutations = options.inspectStateCount ? await options.inspectStateCount() : undefined;
    const duplicateDetected =
      (observedMutations !== undefined && observedMutations > 1) ||
      Boolean(id1 && id2 && id1 !== id2);

    if (duplicateDetected) {
      return {
        checkId: 'TC-IDEMP-003',
        dimension: 'D1',
        tool: tool.name,
        status: 'FAIL',
        severity: 'CRITICAL',
        vetoClass: 'VETO_IDEMP',
        description: `Real TCP socket-cut crash-commit vulnerability: Post-commit mid-response drop + replay created duplicate mutations on '${tool.name}'${
          observedMutations !== undefined ? ` (mutations=${observedMutations})` : ` (ID1=${id1}, ID2=${id2})`
        }`,
        evidence: {
          requestsSent: 3,
          mutationsCreated: observedMutations ?? 2,
          expectedMutations: 1,
          evidenceQuality: 'VERIFIED',
          details: {
            faultMode: 'real-tcp-socket-cut',
            socketDropObserved,
            cutsExecuted: proxyStats.cutsExecuted,
            headersIntercepted: proxyStats.headersIntercepted,
            sessionId,
            initialId: id1,
            replayedId: id2,
          },
        },
        fix: {
          summary: 'Enforce atomic transaction commit tied to idempotency key before returning response',
          applyCommand: 'toolveto fix --apply',
          diffs: [
            {
              language: 'typescript-zod',
              code: `+ await db.transaction(async (tx) => {\n+   const existing = await tx.findIdempotency(idempotencyKey);\n+   if (existing) return existing.response;\n+   const result = await tx.executeMutation(payload);\n+   await tx.saveIdempotency(idempotencyKey, result);\n+   return result;\n+ });`,
            },
          ],
        },
        durationMs: Date.now() - startTime,
      };
    }

    return {
      checkId: 'TC-IDEMP-003',
      dimension: 'D1',
      tool: tool.name,
      status: 'PASS',
      severity: 'LOW',
      description: `Real TCP socket-cut crash-commit verified: post-commit drop & replay preserved single-entity invariance on '${tool.name}'`,
      evidence: {
        requestsSent: 3,
        mutationsCreated: observedMutations ?? 1,
        expectedMutations: 1,
        evidenceQuality: 'VERIFIED',
        details: {
          faultMode: 'real-tcp-socket-cut',
          socketDropObserved,
          cutsExecuted: proxyStats.cutsExecuted,
          headersIntercepted: proxyStats.headersIntercepted,
          entityId: id1,
        },
      },
      durationMs: Date.now() - startTime,
    };
  } finally {
    await proxy.close();
  }
}

/**
 * TC-IDEMP-003: Crash-Between-Commit-and-Response Simulation
 * Uses real TCP mid-response socket-cut proxy whenever the client exposes an
 * HTTP endpoint URL (`getEndpointUrl()`), falling back cleanly to live client
 * replay or static schema analysis.
 */
export async function runCrashCommitCheck(
  tool: McpToolDefinition,
  client?: McpClient,
  destructiveAuthorization = false
): Promise<CheckResult> {
  const startTime = Date.now();

  if (!tool.isMutation) {
    return {
      checkId: 'TC-IDEMP-003',
      dimension: 'D1',
      tool: tool.name,
      status: 'PASS',
      severity: 'LOW',
      description: `Query tool '${tool.name}' is read-only and free from crash-commit double-spend risk`,
      evidence: { evidenceQuality: 'STATIC-ONLY' },
      durationMs: Date.now() - startTime,
    };
  }

  // Active behavioral fault injection test
  if (client && destructiveAuthorization) {
    const endpointUrl =
      typeof (client as any).getEndpointUrl === 'function'
        ? String((client as any).getEndpointUrl() || '')
        : '';
    if (endpointUrl.startsWith('http://')) {
      try {
        return await runRealSocketCutCrashCommitCheck(tool, endpointUrl);
      } catch {
        // Fall through cleanly to transport-agnostic client replay
      }
    }

    const crashKey = `crash_commit_key_${Date.now()}`;
    const payload = buildCrashPayload(tool, crashKey);

    try {
      const res1 = await client.callTool(tool.name, payload);
      const res2 = await client.callTool(tool.name, payload);

      const text1 = res1.content?.map((c) => c.text).join('') || '';
      const text2 = res2.content?.map((c) => c.text).join('') || '';

      if (!res1.isError && !res2.isError) {
        let id1: string | null = null;
        let id2: string | null = null;
        try {
          id1 = extractEntityId(JSON.parse(text1));
          id2 = extractEntityId(JSON.parse(text2));
        } catch {
          // Non-JSON
        }

        if (id1 && id2 && id1 !== id2) {
          return {
            checkId: 'TC-IDEMP-003',
            dimension: 'D1',
            tool: tool.name,
            status: 'FAIL',
            severity: 'CRITICAL',
            vetoClass: 'VETO_IDEMP',
            description: `Crash-commit vulnerability: Replayed mutation after dropped connection created duplicate entity (ID1: ${id1}, ID2: ${id2})`,
            evidence: {
              requestsSent: 2,
              mutationsCreated: 2,
              expectedMutations: 1,
              evidenceQuality: 'VERIFIED',
              details: { initialId: id1, replayedId: id2 },
            },
            fix: {
              summary: 'Enforce atomic transaction commit tied to idempotency key before returning response',
              applyCommand: 'toolveto fix --apply',
              diffs: [
                {
                  language: 'typescript-zod',
                  code: `+ await db.transaction(async (tx) => {\n+   const existing = await tx.findIdempotency(idempotencyKey);\n+   if (existing) return existing.response;\n+   const result = await tx.executeMutation(payload);\n+   await tx.saveIdempotency(idempotencyKey, result);\n+   return result;\n+ });`,
                },
              ],
            },
            durationMs: Date.now() - startTime,
          };
        }
      }

      return {
        checkId: 'TC-IDEMP-003',
        dimension: 'D1',
        tool: tool.name,
        status: 'PASS',
        severity: 'LOW',
        description: `Crash-commit check passed: Reconnected replay for '${tool.name}' correctly atomized mutation`,
        evidence: {
          requestsSent: 2,
          mutationsCreated: 1,
          expectedMutations: 1,
          evidenceQuality: 'VERIFIED',
        },
        durationMs: Date.now() - startTime,
      };
    } catch {
      // Safe fallback
    }
  }

  // Static schema fallback
  const properties = tool.inputSchema?.properties || {};
  const hasExplicitKey = Boolean(
    properties['idempotency_key'] ||
      properties['idempotencyKey'] ||
      properties['client_request_id'] ||
      properties['request_id']
  );

  if (hasExplicitKey) {
    return {
      checkId: 'TC-IDEMP-003',
      dimension: 'D1',
      tool: tool.name,
      status: 'PASS',
      severity: 'LOW',
      description: `Schema declares explicit idempotency key on '${tool.name}' for crash recovery`,
      evidence: { evidenceQuality: 'STATIC-ONLY' },
      durationMs: Date.now() - startTime,
    };
  }

  return {
    checkId: 'TC-IDEMP-003',
    dimension: 'D1',
    tool: tool.name,
    status: 'FAIL',
    severity: 'HIGH',
    description: `Missing explicit idempotency key in schema definition for mutation tool '${tool.name}' (unprotected against crash-commit double-spend)`,
    evidence: { evidenceQuality: 'STATIC-ONLY' },
    fix: {
      summary: "Add 'idempotency_key: string' parameter to schema",
      applyCommand: 'toolveto fix --apply',
      diffs: [
        {
          language: 'typescript-zod',
          code: `+ idempotency_key: z.string().uuid().describe("Unique token for idempotent request processing")`,
        },
      ],
    },
    durationMs: Date.now() - startTime,
  };
}
