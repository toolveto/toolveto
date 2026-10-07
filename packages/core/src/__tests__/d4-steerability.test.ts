import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { runDescriptionAmbiguityCheck, runParamSteerabilityCheck } from '../checks/d4-steerability/ambiguity.js';
import { McpToolDefinition } from '../types.js';

describe('D4: Tool Steerability & Semantic Ambiguity Battery', () => {
  describe('TC-STEER-001: Description Ambiguity', () => {
    it('should warn when tool description is missing or terse (<20 chars)', () => {
      const tool: McpToolDefinition = {
        name: 'do_action',
        description: 'Short desc',
        inputSchema: { type: 'object', properties: {} },
      };

      const res = runDescriptionAmbiguityCheck(tool, [tool]);
      assert.strictEqual(res.checkId, 'TC-STEER-001');
      assert.strictEqual(res.status, 'WARN');
      assert.strictEqual(res.severity, 'MEDIUM');
      assert.ok(res.description.includes('terse description (<20 chars)'));
      assert.strictEqual(res.evidence.details?.descriptionLength, 10);
      assert.ok(res.fix);
    });

    it('should warn when tool shares naming root with another tool and description is <50 chars', () => {
      const toolA: McpToolDefinition = {
        name: 'create_user',
        description: 'Creates a user account',
        inputSchema: { type: 'object', properties: {} },
      };
      const toolB: McpToolDefinition = {
        name: 'create_user_admin',
        description: 'Creates an admin user account in the system',
        inputSchema: { type: 'object', properties: {} },
      };

      const res = runDescriptionAmbiguityCheck(toolA, [toolA, toolB]);
      assert.strictEqual(res.checkId, 'TC-STEER-001');
      assert.strictEqual(res.status, 'WARN');
      assert.ok(res.description.includes('shares naming root'));
      assert.deepStrictEqual(res.evidence.details?.similarTools, ['create_user_admin']);
    });

    it('should pass when tool has distinguishing description (>50 chars) despite naming overlap', () => {
      const toolA: McpToolDefinition = {
        name: 'create_user',
        description: 'Creates a standard non-privileged customer user profile and provisions default workspace settings.',
        inputSchema: { type: 'object', properties: {} },
      };
      const toolB: McpToolDefinition = {
        name: 'create_user_admin',
        description: 'Creates an administrative superuser account with full access to tenant configuration.',
        inputSchema: { type: 'object', properties: {} },
      };

      const res = runDescriptionAmbiguityCheck(toolA, [toolA, toolB]);
      assert.strictEqual(res.checkId, 'TC-STEER-001');
      assert.strictEqual(res.status, 'PASS');
      assert.strictEqual(res.severity, 'LOW');
      assert.ok(res.description.includes('sufficient semantic steerability context'));
    });

    it('should pass when tool has adequate description without any naming overlap', () => {
      const tool: McpToolDefinition = {
        name: 'send_webhook_notification',
        description: 'Dispatches signed webhook payload to remote customer endpoints.',
        inputSchema: { type: 'object', properties: {} },
      };

      const res = runDescriptionAmbiguityCheck(tool, [tool]);
      assert.strictEqual(res.checkId, 'TC-STEER-001');
      assert.strictEqual(res.status, 'PASS');
    });
  });

  describe('TC-STEER-002: Parameter Steerability Guidance', () => {
    it('should warn when sensitive parameter lacks format, pattern, or description', () => {
      const tool: McpToolDefinition = {
        name: 'lookup_account',
        description: 'Searches for customer profile record',
        inputSchema: {
          type: 'object',
          properties: {
            user_id: { type: 'string' },
            created_date: { type: 'string' },
          },
        },
      };

      const res = runParamSteerabilityCheck(tool);
      assert.strictEqual(res.checkId, 'TC-STEER-002');
      assert.strictEqual(res.status, 'WARN');
      assert.strictEqual(res.severity, 'LOW');
      assert.deepStrictEqual(res.evidence.details?.unguidedParams, ['user_id', 'created_date']);
    });

    it('should pass when sensitive parameters include format or regex pattern', () => {
      const tool: McpToolDefinition = {
        name: 'lookup_account',
        description: 'Searches for customer profile record',
        inputSchema: {
          type: 'object',
          properties: {
            user_id: { type: 'string', format: 'uuid' },
            created_date: { type: 'string', pattern: '^\\d{4}-\\d{2}-\\d{2}$' },
          },
        },
      };

      const res = runParamSteerabilityCheck(tool);
      assert.strictEqual(res.checkId, 'TC-STEER-002');
      assert.strictEqual(res.status, 'PASS');
    });

    it('should pass when sensitive parameters provide description with examples (e.g.)', () => {
      const tool: McpToolDefinition = {
        name: 'send_invoice',
        description: 'Sends an invoice email to client',
        inputSchema: {
          type: 'object',
          properties: {
            customer_email: { type: 'string', description: 'Target email address (e.g. billing@company.com)' },
          },
        },
      };

      const res = runParamSteerabilityCheck(tool);
      assert.strictEqual(res.checkId, 'TC-STEER-002');
      assert.strictEqual(res.status, 'PASS');
    });

    it('should pass when tool has only non-sensitive parameters', () => {
      const tool: McpToolDefinition = {
        name: 'set_page_limit',
        description: 'Adjusts the pagination display count',
        inputSchema: {
          type: 'object',
          properties: {
            limit: { type: 'number' },
            enabled: { type: 'boolean' },
          },
        },
      };

      const res = runParamSteerabilityCheck(tool);
      assert.strictEqual(res.checkId, 'TC-STEER-002');
      assert.strictEqual(res.status, 'PASS');
    });
  });
});
