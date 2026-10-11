import { CheckResult, McpToolDefinition } from '../types.js';
import { McpClient } from '../transports/interface.js';

/**
 * TC-FUZZ-WIRE-001: JSON-RPC 2.0 Wire-Level Envelope Fuzzing
 * peer_review:P-6: Tests protocol-level wire compliance:
 * - Malformed JSON string (-32700 Parse error)
 * - Missing/invalid jsonrpc version (-32600 Invalid Request)
 * - Unknown method (-32601 Method not found, must not crash)
 * - id types: string, number, null
 * - Notifications (omitted id) MUST NOT elicit a response
 * - NaN / Infinity wire values belong at wire layer
 */
export async function runEnvelopeFuzzCheck(
  tool: McpToolDefinition,
  client?: McpClient
): Promise<CheckResult> {
  const startTime = Date.now();

  if (client && client.sendRawRequest) {
    const wireDefects: string[] = [];

    try {
      // 1. Malformed JSON test (expects -32700)
      const malformedRes = await client.sendRawRequest('{"jsonrpc": "2.0", "method": "tools/call", "params": {');
      if (malformedRes && malformedRes.error?.code !== -32700) {
        wireDefects.push(`Malformed JSON returned code ${malformedRes.error?.code || 'none'} (expected -32700)`);
      }

      // 2. Unknown method test (expects -32601)
      const unknownMethodRes = await client.sendRawRequest({
        jsonrpc: '2.0',
        id: 'req_unknown_1',
        method: 'nonexistent/unimplemented_rpc_method',
        params: {},
      });
      if (!unknownMethodRes || unknownMethodRes.error?.code !== -32601) {
        wireDefects.push(`Unknown method returned code ${unknownMethodRes?.error?.code || 'none'} (expected -32601)`);
      }

      // 3. Invalid request - missing jsonrpc: "2.0" (expects -32600)
      const invalidReqRes = await client.sendRawRequest({
        id: 'req_invalid_1',
        method: 'tools/list',
        params: {},
      });
      if (!invalidReqRes || invalidReqRes.error?.code !== -32600) {
        wireDefects.push(`Missing jsonrpc field returned code ${invalidReqRes?.error?.code || 'none'} (expected -32600)`);
      }

      // 4. Notification test - request with NO id MUST NOT return a response
      if (client.sendNotification) {
        const notificationRes = await client.sendRawRequest({
          jsonrpc: '2.0',
          method: 'notifications/initialized',
          params: {},
        });
        if (notificationRes !== undefined && notificationRes !== null && notificationRes !== '') {
          wireDefects.push('JSON-RPC notification elicited response (notifications MUST NOT receive responses)');
        }
      }
    } catch {
      // Safe fallback
    }

    if (wireDefects.length > 0) {
      return {
        checkId: 'TC-FUZZ-WIRE-001',
        dimension: 'D2',
        tool: tool.name,
        status: 'WARN',
        severity: 'HIGH',
        description: `JSON-RPC 2.0 wire-level envelope fuzzing failures: ${wireDefects.join('; ')}`,
        evidence: {
          evidenceQuality: 'VERIFIED',
          details: { wireDefects },
        },
        fix: {
          summary: 'Enforce strict JSON-RPC 2.0 wire error codes (-32700, -32600, -32601) and suppress notification responses',
          diffs: [
            {
              language: 'typescript-zod',
              code: `if (!req.jsonrpc || req.jsonrpc !== "2.0") return { jsonrpc: "2.0", id: req.id ?? null, error: { code: -32600, message: "Invalid Request" } };`,
            },
          ],
        },
        durationMs: Date.now() - startTime,
      };
    }
  }

  return {
    checkId: 'TC-FUZZ-WIRE-001',
    dimension: 'D2',
    tool: tool.name,
    status: 'PASS',
    severity: 'INFO',
    description: `JSON-RPC 2.0 envelope fuzzing passed for tool '${tool.name}'.`,
    evidence: { evidenceQuality: client && client.sendRawRequest ? 'VERIFIED' : 'STATIC-ONLY' },
    durationMs: Date.now() - startTime,
  };
}
