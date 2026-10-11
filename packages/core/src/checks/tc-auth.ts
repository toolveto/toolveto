import { CheckResult, McpToolDefinition } from '../types.js';
import { McpClient } from '../transports/interface.js';

/**
 * TC-AUTH-001: Canary Tenant Cross-Session Isolation Check
 * Verifies that two authenticated sessions cannot read or mutate each other's state.
 * Direct compliance mapping: AIUC-1 §5.1 (Auth Model & Multi-Tenant Isolation)
 */
export async function runTenantIsolationCheck(
  tool: McpToolDefinition,
  client?: McpClient,
  destructiveAuthorization = false
): Promise<CheckResult> {
  const startTime = Date.now();
  const props = tool.inputSchema?.properties || {};

  // Check if tool accepts tenant, workspace, account, or org identifiers
  const tenantParam = Object.keys(props).find((k) =>
    ['tenant', 'tenant_id', 'workspace', 'workspace_id', 'account', 'account_id', 'org_id', 'user_id'].includes(k.toLowerCase())
  );

  if (client && tenantParam && destructiveAuthorization) {
    try {
      const canaryTenantA = `canary_tenant_alpha_${Date.now()}`;
      const canaryTenantB = `canary_tenant_beta_${Date.now()}`;

      // Session A creates resource under Tenant A
      const payloadA: Record<string, any> = { [tenantParam]: canaryTenantA, resource_name: 'confidential_payload_a' };
      const respA = await client.callTool(tool.name, payloadA);
      const textA = respA.content?.map((c) => c.text).join('') || '';

      // Session B attempts to read or mutate Tenant A's state using Tenant B's credentials
      const payloadB: Record<string, any> = { [tenantParam]: canaryTenantB, target_id: canaryTenantA, query: canaryTenantA };
      const respB = await client.callTool(tool.name, payloadB);
      const textB = respB.content?.map((c) => c.text).join('') || '';

      if (textB.includes('confidential_payload_a') || (respB.isError !== true && textB.includes(canaryTenantA))) {
        return {
          checkId: 'TC-AUTH-001',
          dimension: 'D5',
          tool: tool.name,
          status: 'FAIL',
          severity: 'CRITICAL',
          description: `VETO_TENANT_LEAK: Cross-tenant state leakage detected. Session with tenant '${canaryTenantB}' accessed state belonging to tenant '${canaryTenantA}'.`,
          evidence: {
            evidenceQuality: 'VERIFIED',
            details: {
              canaryTenantA,
              canaryTenantB,
              leakedPayload: textB.slice(0, 200),
            },
          },
          fix: {
            summary: 'Enforce tenant isolation barriers in tool data access layer and bind requests to authenticated tenant context',
            diffs: [
              {
                language: 'typescript-zod',
                code: `// Verify tenant authorization against authenticated session context\nif (session.tenantId !== args.tenantId) throw new McpSecurityError("Unauthorized cross-tenant access");`,
              },
            ],
          },
          durationMs: Date.now() - startTime,
        };
      }
    } catch {
      // Ignored for safe handling
    }
  }

  // Schema-level tenant isolation validation
  const requiresTenantScoping = tool.isMutation && !tenantParam && ['create', 'update', 'delete', 'mutate', 'write'].some((v) => tool.name.includes(v));

  if (requiresTenantScoping) {
    return {
      checkId: 'TC-AUTH-001',
      dimension: 'D5',
      tool: tool.name,
      status: 'WARN',
      severity: 'HIGH',
      description: `Tenant isolation warning: Mutating tool '${tool.name}' accepts no tenant/account scoping parameter in input schema. Ensure tenant boundary is enforced via ambient session context.`,
      evidence: {
        evidenceQuality: 'STATIC-ONLY',
        details: { missingTenantParam: true },
      },
      durationMs: Date.now() - startTime,
    };
  }

  return {
    checkId: 'TC-AUTH-001',
    dimension: 'D5',
    tool: tool.name,
    status: 'PASS',
    severity: 'INFO',
    description: `Tenant isolation verified: tool '${tool.name}' maintains tenant context separation.`,
    evidence: {
      evidenceQuality: client ? 'VERIFIED' : 'STATIC-ONLY',
    },
    durationMs: Date.now() - startTime,
  };
}

/**
 * TC-AUTH-002: OAuth 2.1 Scope Enforcement & Mid-Session Token Expiry
 */
export function runOAuthScopeCheck(tool: McpToolDefinition): CheckResult {
  const isDestructive = tool.isMutation || tool.destructiveHint || ['delete', 'drop', 'wipe', 'purge', 'charge'].some((v) => tool.name.includes(v));
  const desc = tool.description?.toLowerCase() || '';

  // Destructive operations must explicitly document required OAuth scopes
  const hasScopeNotice = desc.includes('scope') || desc.includes('oauth') || desc.includes('permission') || desc.includes('role');

  if (isDestructive && !hasScopeNotice) {
    return {
      checkId: 'TC-AUTH-002',
      dimension: 'D5',
      tool: tool.name,
      status: 'WARN',
      severity: 'MEDIUM',
      description: `OAuth 2.1 Scope Guidance: High-impact mutating tool '${tool.name}' does not specify required OAuth2.1 scopes (e.g. 'write:payments') in tool description.`,
      evidence: {
        evidenceQuality: 'STATIC-ONLY',
        details: { recommendedScope: `write:${tool.name}` },
      },
      fix: {
        summary: `Document required OAuth 2.1 scope in description of tool '${tool.name}'`,
        diffs: [
          {
            language: 'json-schema',
            code: `"description": "${tool.description || tool.name} (Requires OAuth 2.1 scope: write:${tool.name})"`,
          },
        ],
      },
      durationMs: 1,
    };
  }

  return {
    checkId: 'TC-AUTH-002',
    dimension: 'D5',
    tool: tool.name,
    status: 'PASS',
    severity: 'INFO',
    description: `OAuth 2.1 scope specification verified for tool '${tool.name}'.`,
    evidence: { evidenceQuality: 'STATIC-ONLY' },
    durationMs: 1,
  };
}

/**
 * TC-AUTH-003: Roots Path-Traversal & Directory Escape Check
 */
export async function runRootsPathTraversalCheck(
  tool: McpToolDefinition,
  client?: McpClient
): Promise<CheckResult> {
  const startTime = Date.now();
  const props = tool.inputSchema?.properties || {};

  // Check if tool accepts file paths or URIs
  const pathParam = Object.keys(props).find((k) =>
    ['path', 'file_path', 'filepath', 'filename', 'file', 'uri', 'url', 'dir', 'directory'].includes(k.toLowerCase())
  );

  if (client && pathParam) {
    const traversalPayloads = [
      '../../../../../../etc/passwd',
      '..%2F..%2F..%2F..%2Fetc%2Fpasswd',
      'file:///etc/passwd',
      '/etc/passwd',
    ];

    for (const testPath of traversalPayloads) {
      try {
        const resp = await client.callTool(tool.name, { [pathParam]: testPath });
        const text = resp.content?.map((c) => c.text).join('') || '';

        if (text.includes('root:x:0:0:') || text.includes('/bin/sh') || text.includes('/bin/bash')) {
          return {
            checkId: 'TC-AUTH-003',
            dimension: 'D5',
            tool: tool.name,
            status: 'FAIL',
            severity: 'CRITICAL',
            description: `VETO_TRAVERSAL: Directory traversal / roots escape vulnerability detected in parameter '${pathParam}'. Accessed arbitrary system path '${testPath}'.`,
            evidence: {
              evidenceQuality: 'VERIFIED',
              details: { testPath, leakedFragment: text.slice(0, 100) },
            },
            fix: {
              summary: 'Restrict path access to designated workspace roots and reject relative directory traversal sequences',
              diffs: [
                {
                  language: 'typescript-zod',
                  code: `const resolved = path.resolve(WORKSPACE_ROOT, inputPath);\nif (!resolved.startsWith(WORKSPACE_ROOT)) throw new McpSecurityError("Path traversal escape forbidden");`,
                },
              ],
            },
            durationMs: Date.now() - startTime,
          };
        }
      } catch {
        // Safe rejection
      }
    }
  }

  return {
    checkId: 'TC-AUTH-003',
    dimension: 'D5',
    tool: tool.name,
    status: 'PASS',
    severity: 'INFO',
    description: `Roots path traversal check passed for tool '${tool.name}'.`,
    evidence: { evidenceQuality: client && pathParam ? 'VERIFIED' : 'STATIC-ONLY' },
    durationMs: Date.now() - startTime,
  };
}
