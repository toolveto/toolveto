import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { runTenantIsolationCheck, runOAuthScopeCheck, runRootsPathTraversalCheck } from '../checks/tc-auth.js';
import { runResourceListCheck, runResourceReadCheck, runServerCapabilityCheck } from '../checks/resources-coverage.js';
import { runCancellationCheck, runLatencyProfilingCheck } from '../checks/cancellation-latency.js';
import { runAnnotationCrossCheck } from '../checks/annotation-cross-check.js';
import { runEnvelopeFuzzCheck } from '../checks/envelope-fuzz.js';
import { McpToolDefinition, McpResourceDefinition } from '../types.js';
import { InMemoryMcpClient } from '../transports/in-memory.js';

describe('7 Must-Add Enterprise Verification Checks', () => {
  it('TC-AUTH-001: should trigger VETO_TENANT_LEAK when cross-tenant data leaks', async () => {
    const mutatingTool: McpToolDefinition = {
      name: 'manage_tenant_workspace',
      isMutation: true,
      inputSchema: {
        type: 'object',
        properties: { tenant_id: { type: 'string' }, target_id: { type: 'string' } },
      },
    };

    const client = new InMemoryMcpClient([
      {
        definition: mutatingTool,
        handler: async (args) => {
          if (args.target_id?.includes('canary_tenant_alpha')) {
            return { content: [{ type: 'text', text: 'confidential_payload_a leaked to tenant B' }] };
          }
          return { content: [{ type: 'text', text: 'ok' }] };
        },
      },
    ]);

    const result = await runTenantIsolationCheck(mutatingTool, client, true);
    assert.strictEqual(result.status, 'FAIL');
    assert.strictEqual(result.severity, 'CRITICAL');
    assert.ok(result.description.includes('VETO_TENANT_LEAK'));
  });

  it('TC-AUTH-002: should warn on destructive tool lacking OAuth 2.1 scope documentation', () => {
    const destructiveTool: McpToolDefinition = {
      name: 'delete_customer_database',
      isMutation: true,
      description: 'Deletes production database instance',
      inputSchema: { type: 'object', properties: {} },
    };

    const result = runOAuthScopeCheck(destructiveTool);
    assert.strictEqual(result.status, 'WARN');
    assert.strictEqual(result.severity, 'MEDIUM');
    assert.ok(result.description.includes('OAuth 2.1 Scope'));
  });

  it('TC-AUTH-003: should flag VETO_TRAVERSAL on directory escape', async () => {
    const fileTool: McpToolDefinition = {
      name: 'read_workspace_file',
      isMutation: false,
      inputSchema: {
        type: 'object',
        properties: { file_path: { type: 'string' } },
      },
    };

    const client = new InMemoryMcpClient([
      {
        definition: fileTool,
        handler: async (args) => {
          if (args.file_path?.includes('/etc/passwd')) {
            return { content: [{ type: 'text', text: 'root:x:0:0:root:/root:/bin/bash' }] };
          }
          return { content: [{ type: 'text', text: 'file content' }] };
        },
      },
    ]);

    const result = await runRootsPathTraversalCheck(fileTool, client);
    assert.strictEqual(result.status, 'FAIL');
    assert.strictEqual(result.severity, 'CRITICAL');
    assert.ok(result.description.includes('VETO_TRAVERSAL'));
  });

  it('TC-RES-001 & TC-RES-002: should validate resources pagination and context budget', async () => {
    const largeResources: McpResourceDefinition[] = Array.from({ length: 60 }, (_, i) => ({
      uri: `schema://dataset/${i}`,
      name: `Resource ${i}`,
    }));

    const res1 = await runResourceListCheck(largeResources);
    assert.strictEqual(res1.status, 'WARN');
    assert.ok(res1.description.includes('pagination'));

    const mockClient: any = {
      readResource: async () => ({
        contents: [{ uri: 'schema://dataset/0', text: 'Z'.repeat(40000) }],
      }),
    };

    const res2 = await runResourceReadCheck(largeResources, mockClient);
    assert.strictEqual(res2.status, 'FAIL');
    assert.strictEqual(res2.severity, 'CRITICAL');
    assert.ok(res2.description.includes('context bomb'));
  });

  it('TC-CAP-001: should audit server sampling and elicitation escalations', async () => {
    const escalatingClient: any = {
      getCapabilities: async () => ({
        sampling: { maxTokens: 2000 },
        elicitation: { enabled: true },
      }),
    };

    const result = await runServerCapabilityCheck(escalatingClient);
    assert.strictEqual(result.status, 'WARN');
    assert.strictEqual(result.severity, 'HIGH');
    assert.ok(result.description.includes('Server-to-client escalation'));
  });

  it('TC-CANCEL-001: should verify cancellation halts mutations', async () => {
    const mutatingTool: McpToolDefinition = {
      name: 'transfer_funds',
      isMutation: true,
      inputSchema: { type: 'object', properties: { amount: { type: 'number' } } },
    };

    // Client that commits mutation even after cancelled
    const stubbornClient: any = {
      sendNotification: async () => {},
      callTool: async () => ({
        isError: false,
        content: [{ type: 'text', text: 'Created transfer charge_id_999' }],
      }),
    };

    const result = await runCancellationCheck(mutatingTool, stubbornClient, true);
    assert.strictEqual(result.status, 'WARN');
    assert.strictEqual(result.severity, 'HIGH');
    assert.ok(result.description.includes('Cancellation resilience failure'));
  });

  it('TC-ANNOTATION-001: should trigger automatic HIGH contradiction if idempotentHint: true fails replay', async () => {
    const lyingTool: McpToolDefinition = {
      name: 'create_order',
      isMutation: true,
      idempotentHint: true,
      inputSchema: { type: 'object', properties: {} },
    };

    const result = await runAnnotationCrossCheck(lyingTool, undefined, false); // d1ReplayPassed = false
    assert.strictEqual(result.status, 'FAIL');
    assert.strictEqual(result.severity, 'HIGH');
    assert.ok(result.description.includes('Annotation contradiction'));
    assert.ok(result.description.includes('idempotentHint'));
  });

  it('TC-ANNOTATION-001: should trigger automatic HIGH contradiction if readOnlyHint: true is mutation', async () => {
    const fakeReadTool: McpToolDefinition = {
      name: 'delete_user_record',
      isMutation: true,
      readOnlyHint: true,
      inputSchema: { type: 'object', properties: {} },
    };

    const result = await runAnnotationCrossCheck(fakeReadTool, undefined, true);
    assert.strictEqual(result.status, 'FAIL');
    assert.strictEqual(result.severity, 'HIGH');
    assert.ok(result.description.includes('readOnlyHint'));
  });

  it('TC-FUZZ-WIRE-001: should flag JSON-RPC 2.0 wire-level protocol defects', async () => {
    const tool: McpToolDefinition = {
      name: 'query_status',
      inputSchema: { type: 'object', properties: {} },
    };

    const nonCompliantClient: any = {
      sendRawRequest: async (req: any) => {
        // Returns 500 error instead of -32700 on malformed JSON
        if (typeof req === 'string') {
          return { jsonrpc: '2.0', error: { code: -32000, message: 'Server crash' } };
        }
        return { jsonrpc: '2.0', id: req.id, result: {} };
      },
    };

    const result = await runEnvelopeFuzzCheck(tool, nonCompliantClient);
    assert.strictEqual(result.status, 'WARN');
    assert.strictEqual(result.severity, 'HIGH');
    assert.ok(result.description.includes('JSON-RPC 2.0 wire-level envelope fuzzing failures'));
  });

  it('TC-IDEMP-004: should detect delayed replay state corruption across sessions', async () => {
    let callNum = 0;
    const leakyTool: McpToolDefinition = {
      name: 'create_invoice',
      isMutation: true,
      inputSchema: {
        type: 'object',
        properties: { idempotency_key: { type: 'string' }, amount: { type: 'number' } },
      },
    };

    const client = new InMemoryMcpClient([
      {
        definition: leakyTool,
        handler: async () => {
          callNum++;
          return { content: [{ type: 'text', text: JSON.stringify({ invoice_id: `inv_${callNum}` }) }] };
        },
      },
    ]);

    const { runDelayedReplayCheck } = await import('../checks/delayed-replay.js');
    const result = await runDelayedReplayCheck(leakyTool, client, true);
    assert.strictEqual(result.status, 'FAIL');
    assert.strictEqual(result.severity, 'CRITICAL');
    assert.strictEqual(result.checkId, 'TC-IDEMP-004');
    assert.ok(result.description.includes('Delayed replay failure'));
  });

  it('TC-RACE-001: should detect resurrection race in heterogeneous interleaving', async () => {
    const updateTool: McpToolDefinition = {
      name: 'update_account',
      isMutation: true,
      inputSchema: { type: 'object', properties: { id: { type: 'string' } } },
    };
    const deleteTool: McpToolDefinition = {
      name: 'delete_account',
      isMutation: true,
      inputSchema: { type: 'object', properties: { id: { type: 'string' } } },
    };
    const readTool: McpToolDefinition = {
      name: 'get_account',
      isMutation: false,
      inputSchema: { type: 'object', properties: { id: { type: 'string' } } },
    };

    const client = new InMemoryMcpClient([
      {
        definition: updateTool,
        handler: async () => ({ content: [{ type: 'text', text: 'account updated' }] }),
      },
      {
        definition: deleteTool,
        handler: async () => ({ content: [{ type: 'text', text: 'account deleted' }] }),
      },
      {
        definition: readTool,
        handler: async () => ({ content: [{ type: 'text', text: 'account status: updated' }] }),
      },
    ]);

    const { runHeterogeneousInterleavingCheck } = await import('../checks/delayed-replay.js');
    const result = await runHeterogeneousInterleavingCheck([updateTool, deleteTool, readTool], client, true);
    assert.strictEqual(result.status, 'FAIL');
    assert.strictEqual(result.severity, 'CRITICAL');
    assert.strictEqual(result.checkId, 'TC-RACE-001');
    assert.ok(result.description.includes('resurrected'));
  });

  it('TC-IDEMP-003: should detect crash-commit duplicate entity creation upon reconnect', async () => {
    let callIdx = 0;
    const mutateTool: McpToolDefinition = {
      name: 'charge_subscription',
      isMutation: true,
      inputSchema: {
        type: 'object',
        properties: { request_id: { type: 'string' }, amount: { type: 'number' } },
      },
    };

    const client = new InMemoryMcpClient([
      {
        definition: mutateTool,
        handler: async () => {
          callIdx++;
          return { content: [{ type: 'text', text: JSON.stringify({ charge_id: `ch_attempt_${callIdx}` }) }] };
        },
      },
    ]);

    const { runCrashCommitCheck } = await import('../checks/d1-idempotency/crash-commit.js');
    const result = await runCrashCommitCheck(mutateTool, client, true);
    assert.strictEqual(result.status, 'FAIL');
    assert.strictEqual(result.severity, 'CRITICAL');
    assert.strictEqual(result.checkId, 'TC-IDEMP-003');
    assert.ok(result.description.includes('Crash-commit vulnerability'));
  });

  it('TC-LATENCY-001: should profile p50/p95 latency and alert on slow mutation tools', async () => {
    const slowTool: McpToolDefinition = {
      name: 'slow_database_export',
      isMutation: false,
      inputSchema: { type: 'object', properties: {} },
    };

    const slowClient = new InMemoryMcpClient([
      {
        definition: slowTool,
        handler: async () => {
          await new Promise((r) => setTimeout(r, 60));
          return { content: [{ type: 'text', text: 'done' }] };
        },
      },
    ]);

    const result = await runLatencyProfilingCheck(slowTool, slowClient, true);
    assert.strictEqual(result.checkId, 'TC-LATENCY-001');
    assert.strictEqual(result.status, 'PASS');
    assert.ok(result.evidence.details?.p95Ms !== undefined);
  });
});
