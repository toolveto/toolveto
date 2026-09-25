import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { runReadBeforeWritePairingCheck } from '../checks/d5-auditability/pairing.js';
import { runDryRunCheck } from '../checks/d5-auditability/dry-run.js';
import { McpToolDefinition } from '../types.js';

describe('D5: State Auditability Battery', () => {
  it('TC-PAIR-001: should fail blind write mutation that lacks companion inspection tool', () => {
    const mutationOnly: McpToolDefinition = {
      name: 'create_payment',
      isMutation: true,
      inputSchema: { type: 'object', properties: {} },
    };

    const res = runReadBeforeWritePairingCheck(mutationOnly, [mutationOnly]);
    assert.strictEqual(res.checkId, 'TC-PAIR-001');
    assert.strictEqual(res.status, 'FAIL');
    assert.ok(res.description.includes('blind-write'));
    assert.ok(res.fix);
  });

  it('TC-PAIR-001: should pass when paired query inspection tool exists', () => {
    const mutation: McpToolDefinition = {
      name: 'create_payment',
      isMutation: true,
      inputSchema: { type: 'object', properties: {} },
    };
    const query: McpToolDefinition = {
      name: 'get_payment',
      isMutation: false,
      inputSchema: { type: 'object', properties: {} },
    };

    const res = runReadBeforeWritePairingCheck(mutation, [mutation, query]);
    assert.strictEqual(res.status, 'PASS');
  });

  it('TC-DRYRUN-001: should warn on destructive tool lacking dry_run simulation', () => {
    const tool: McpToolDefinition = {
      name: 'delete_database',
      isMutation: true,
      inputSchema: { type: 'object', properties: { db_id: { type: 'string' } } },
    };
    const res = runDryRunCheck(tool);
    assert.strictEqual(res.checkId, 'TC-DRYRUN-001');
    assert.strictEqual(res.status, 'WARN');
    assert.ok(res.fix);
  });

  it('TC-DRYRUN-001: should pass when dry_run parameter is declared in schema', () => {
    const tool: McpToolDefinition = {
      name: 'delete_database',
      isMutation: true,
      inputSchema: {
        type: 'object',
        properties: { db_id: { type: 'string' }, dry_run: { type: 'boolean' } },
      },
    };
    const res = runDryRunCheck(tool);
    assert.strictEqual(res.status, 'PASS');
  });
});
