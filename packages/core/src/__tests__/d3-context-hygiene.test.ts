import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { runTokenBudgetCheck } from '../checks/d3-lite/token-budget.js';
import { runPaginationSchemaCheck } from '../checks/d3-lite/schema-linter.js';
import { runDescriptionClarityCheck } from '../checks/d3-lite/description-clarity.js';
import { runAdditionalPropertiesCheck } from '../checks/d3-lite/additional-properties.js';
import { InMemoryMcpClient } from '../transports/in-memory.js';
import { McpToolDefinition } from '../types.js';

describe('D3: Context & Token Hygiene Battery', () => {
  it('TC-CTX-001: should detect Context Bomb (> 8,000 tokens) as CRITICAL failure with VETO_DATALOSS', async () => {
    const listTool: McpToolDefinition = {
      name: 'list_logs',
      isMutation: false,
      inputSchema: { type: 'object', properties: {} },
    };

    // 40,000 characters ~= 10,000 tokens
    const hugeDump = 'x'.repeat(40000);
    const client = new InMemoryMcpClient([
      {
        definition: listTool,
        handler: async () => ({
          content: [{ type: 'text', text: hugeDump }],
        }),
      },
    ]);

    const result = await runTokenBudgetCheck(listTool, client);
    assert.strictEqual(result.checkId, 'TC-CTX-001');
    assert.strictEqual(result.status, 'FAIL');
    assert.strictEqual(result.severity, 'CRITICAL');
    assert.ok(result.description.includes('Context Bomb'));
  });

  it('TC-CTX-001: should pass compact response well within budget', async () => {
    const listTool: McpToolDefinition = {
      name: 'list_logs',
      isMutation: false,
      inputSchema: { type: 'object', properties: {} },
    };

    const client = new InMemoryMcpClient([
      {
        definition: listTool,
        handler: async () => ({
          content: [{ type: 'text', text: JSON.stringify([{ id: 1 }, { id: 2 }]) }],
        }),
      },
    ]);

    const result = await runTokenBudgetCheck(listTool, client);
    assert.strictEqual(result.status, 'PASS');
  });

  it('TC-SCHEMA-001: should fail list query tool without limit/cursor pagination parameters', () => {
    const unpaginatedList: McpToolDefinition = {
      name: 'list_invoices',
      isMutation: false,
      inputSchema: { type: 'object', properties: { customer_id: { type: 'string' } } },
    };
    const res = runPaginationSchemaCheck(unpaginatedList);
    assert.strictEqual(res.status, 'FAIL');
    assert.strictEqual(res.checkId, 'TC-SCHEMA-001');
    assert.ok(res.fix);
  });

  it('TC-SCHEMA-002: should flag descriptions under 30 characters as too terse', () => {
    const terseTool: McpToolDefinition = {
      name: 'get_user',
      description: 'Find user', // 9 characters
      inputSchema: { type: 'object', properties: {} },
    };
    const res = runDescriptionClarityCheck(terseTool);
    assert.strictEqual(res.status, 'FAIL');
    assert.ok(res.description.includes('too terse'));
  });

  it('TC-SCHEMA-003: should verify additionalProperties is false', () => {
    const strictTool: McpToolDefinition = {
      name: 'strict_tool',
      inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    };
    assert.strictEqual(runAdditionalPropertiesCheck(strictTool).status, 'PASS');

    const laxTool: McpToolDefinition = {
      name: 'lax_tool',
      inputSchema: { type: 'object', properties: {} },
    };
    assert.strictEqual(runAdditionalPropertiesCheck(laxTool).status, 'WARN');
  });
});
