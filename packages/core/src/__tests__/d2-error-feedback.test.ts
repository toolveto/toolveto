import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { runTypeInversionFuzzCheck } from '../checks/d2-error-feedback/type-inversion.js';
import { runHallucinatedParamsCheck } from '../checks/d2-error-feedback/hallucinated-params.js';
import { runSemanticErrorCheck } from '../checks/d2-error-feedback/semantic-error.js';
import { InMemoryMcpClient } from '../transports/in-memory.js';
import { McpToolDefinition } from '../types.js';

describe('D2: Error Feedback & Ergonomics Battery', () => {
  it('TC-FUZZ-001: should flag raw stack traces on fuzzed input', async () => {
    const fragileTool: McpToolDefinition = {
      name: 'calculate',
      inputSchema: {
        type: 'object',
        properties: { count: { type: 'integer' } },
      },
    };

    const client = new InMemoryMcpClient([
      {
        definition: fragileTool,
        handler: async () => ({
          isError: true,
          content: [
            {
              type: 'text',
              text: "Internal error: TypeError: count.toFixed is not a function\n    at Object.calc (/app/server.js:12:4)\n    at processTicksAndRejections (node:internal/process/task_queues:95:5)",
            },
          ],
        }),
      },
    ]);

    const result = await runTypeInversionFuzzCheck(fragileTool, client);
    assert.strictEqual(result.checkId, 'TC-FUZZ-001');
    assert.strictEqual(result.status, 'FAIL');
    assert.ok(result.description.includes('raw stack trace'));
  });

  it('TC-FUZZ-002: should warn if schema allows arbitrary hallucinated parameters', async () => {
    const permissiveTool: McpToolDefinition = {
      name: 'search',
      inputSchema: {
        type: 'object',
        properties: { q: { type: 'string' } },
        additionalProperties: true,
      },
    };

    const result = await runHallucinatedParamsCheck(permissiveTool);
    assert.strictEqual(result.checkId, 'TC-FUZZ-002');
    assert.strictEqual(result.status, 'WARN');
    assert.ok(result.fix);
  });

  it('TC-ERR-001: should catch unhelpful error on invalid date that risks LLM retry loops (Loop 47x)', async () => {
    const dateTool: McpToolDefinition = {
      name: 'book_slot',
      inputSchema: {
        type: 'object',
        properties: { start_date: { type: 'string', format: 'date' } },
      },
    };

    const badClient = new InMemoryMcpClient([
      {
        definition: dateTool,
        handler: async () => ({
          isError: true,
          content: [{ type: 'text', text: '500 Internal Server Error: Failed to parse date' }],
        }),
      },
    ]);

    const result = await runSemanticErrorCheck(dateTool, badClient);
    assert.strictEqual(result.checkId, 'TC-ERR-001');
    assert.strictEqual(result.status, 'FAIL');
    assert.strictEqual(result.severity, 'HIGH');
    assert.ok(result.description.includes('Loop 47x'));
  });

  it('TC-ERR-001: should pass when error provides parameter citation and format example', async () => {
    const dateTool: McpToolDefinition = {
      name: 'book_slot',
      inputSchema: {
        type: 'object',
        properties: { start_date: { type: 'string', format: 'date' } },
      },
    };

    const goodClient = new InMemoryMcpClient([
      {
        definition: dateTool,
        handler: async () => ({
          isError: true,
          content: [
            {
              type: 'text',
              text: "Invalid value for parameter 'start_date'. Expected ISO format YYYY-MM-DD (e.g. '2026-10-15'). Received: 'tomorrow morning'.",
            },
          ],
        }),
      },
    ]);

    const result = await runSemanticErrorCheck(dateTool, goodClient);
    assert.strictEqual(result.status, 'PASS');
  });
});
