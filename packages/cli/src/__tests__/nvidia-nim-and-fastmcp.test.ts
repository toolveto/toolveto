import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import type { McpToolDefinition } from '@toolveto/core';
import {
  checkCommand,
  evaluateNvidiaNimProfile,
  formatNvidiaNimTerminalSection,
  formatNvidiaNimMarkdownSection,
} from '../commands/check.js';
import { fixCommand, patchFastMcpPythonSource } from '../commands/fix.js';

function assertValidPythonSyntax(filePath: string): void {
  execFileSync('python3', ['-m', 'py_compile', filePath], { stdio: 'pipe' });
}

describe('NVIDIA NIM GPU/KV-Cache Profile (--profile nvidia-nim) & FastMCP Auto-Fix', () => {
  it('blocks unpaginated context-bomb MCP tools under --profile nvidia-nim with non-zero exit code and quantifies KV-cache waste', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-nim-fail-'));
    const toolsPath = path.join(tmpDir, 'tools.json');
    const bloatedTools: McpToolDefinition[] = [
      {
        name: 'list_all_transactions',
        description: 'Returns every historical customer transaction across all time without pagination',
        isMutation: false,
        readOnlyHint: true,
        inputSchema: {
          type: 'object',
          properties: { account_id: { type: 'string' } },
          required: ['account_id'],
        },
      },
      {
        name: 'search_audit_logs',
        description: 'Dumps raw audit log events without limit or cursor bounds',
        isMutation: false,
        readOnlyHint: true,
        inputSchema: {
          type: 'object',
          properties: { query: { type: 'string' } },
        },
      },
    ];
    fs.writeFileSync(toolsPath, JSON.stringify(bloatedTools, null, 2), 'utf-8');

    const prevExit = process.exitCode;
    const prevLog = console.log;
    const output: string[] = [];
    console.log = (...args: any[]) => output.push(args.map(String).join(' '));

    try {
      process.exitCode = 0;
      const summary = await checkCommand(toolsPath, {
        profile: 'nvidia-nim',
        json: true,
        noTelemetry: true,
        skipUpdateCheck: true,
      });

      assert.ok(summary, 'checkCommand must return summary');
      const nimReport = (summary as any).nvidiaNimProfile;
      assert.ok(nimReport, 'JSON summary must include nvidiaNimProfile when --profile nvidia-nim is passed');
      assert.strictEqual(nimReport.profile, 'nvidia-nim');
      assert.strictEqual(nimReport.certified, false, 'Unpaginated list/search tools must fail NVIDIA NIM certification');
      assert.strictEqual(nimReport.kvCacheEvictionRisk, 'CRITICAL');
      assert.deepStrictEqual(nimReport.unboundedListTools, ['list_all_transactions', 'search_audit_logs']);
      assert.strictEqual(nimReport.estimatedKvCacheWasteTokensPerCall, 92_000);
      assert.strictEqual(process.exitCode, 1, 'Failed --profile nvidia-nim check must exit non-zero in CI');

      const terminalBanner = formatNvidiaNimTerminalSection(nimReport);
      assert.ok(terminalBanner.includes('🔴 NVIDIA NIM GPU & KV-Cache Certification Profile: BLOCKED (FAIL)'));
      assert.ok(terminalBanner.includes('92,000 tokens/unbounded call'));
      const mdSection = formatNvidiaNimMarkdownSection(nimReport);
      assert.ok(mdSection.includes('NVIDIA NIM GPU & KV-Cache Certification'));
      assert.ok(mdSection.includes('list_all_transactions'));
    } finally {
      console.log = prevLog;
      process.exitCode = prevExit;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('certifies bounded, idempotent, low-risk MCP tools under --profile nvidia-nim with exitCode=0', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-nim-pass-'));
    const toolsPath = path.join(tmpDir, 'tools.json');
    const cleanTools: McpToolDefinition[] = [
      {
        name: 'list_invoices',
        description: 'Lists paginated customer invoices bounded by limit and cursor',
        isMutation: false,
        readOnlyHint: true,
        inputSchema: {
          type: 'object',
          properties: {
            customer_id: { type: 'string', description: 'Customer ID' },
            limit: { type: 'number', minimum: 1, maximum: 50, default: 25, description: 'Max records per page' },
            cursor: { type: 'string', description: 'Pagination cursor' },
          },
          required: ['customer_id'],
          additionalProperties: false,
        },
      },
      {
        name: 'get_invoice',
        description: 'Reads a single invoice by invoice_id',
        isMutation: false,
        readOnlyHint: true,
        inputSchema: {
          type: 'object',
          properties: {
            invoice_id: { type: 'string', description: 'Invoice UUID' },
          },
          required: ['invoice_id'],
          additionalProperties: false,
        },
      },
    ];
    fs.writeFileSync(toolsPath, JSON.stringify(cleanTools, null, 2), 'utf-8');

    const prevExit = process.exitCode;
    const prevLog = console.log;
    console.log = () => {};

    try {
      process.exitCode = 0;
      const summary = await checkCommand(toolsPath, {
        profile: 'nvidia-nim',
        json: true,
        noTelemetry: true,
        skipUpdateCheck: true,
      });
      assert.ok(summary);
      const nimReport = evaluateNvidiaNimProfile(summary, cleanTools);
      assert.strictEqual(nimReport.certified, true, `Expected certified=true, got reasons: ${nimReport.vetoReasons.join('; ')}`);
      assert.strictEqual(nimReport.kvCacheEvictionRisk, 'LOW');
      assert.deepStrictEqual(nimReport.unboundedListTools, []);
      assert.strictEqual(nimReport.estimatedKvCacheWasteTokensPerCall, 0);
      assert.strictEqual(process.exitCode, 0);
    } finally {
      console.log = prevLog;
      process.exitCode = prevExit;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('rejects unrecognized --profile values cleanly with exitCode=1', async () => {
    const prevExit = process.exitCode;
    const prevErr = console.error;
    const errs: string[] = [];
    console.error = (...args: any[]) => errs.push(args.map(String).join(' '));
    try {
      process.exitCode = 0;
      const res = await checkCommand('.', { profile: 'bogus-profile', demo: true });
      assert.strictEqual(res, undefined);
      assert.strictEqual(process.exitCode, 1);
      assert.ok(errs.join('\n').includes("Unknown --profile 'bogus-profile'"));
    } finally {
      console.error = prevErr;
      process.exitCode = prevExit;
    }
  });

  it('patches multi-handler async/sync FastMCP & NeMo Agent Toolkit Python servers in-place and produces valid compilable Python', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-fastmcp-fix-'));
    const serverPy = path.join(tmpDir, 'nat_fastmcp_server.py');

    const originalPy = `from fastmcp import FastMCP

mcp = FastMCP("nvidia-nat-billing")

@mcp.tool()
async def list_orders(customer_id: str, **kwargs):
    return {"customer_id": customer_id, "items": []}

@mcp.tool(name="charge_card")
async def charge_card(amount_cents: int, currency: str = "USD"):
    return {"charged": amount_cents, "currency": currency}

@mcp.tool(destructiveHint=True)
def delete_workspace(workspace_id: str):
    return {"deleted": workspace_id}

@mcp.tool()
def get_health():
    return {"ok": True}
`;
    fs.writeFileSync(serverPy, originalPy, 'utf-8');

    const directRes = patchFastMcpPythonSource(originalPy);
    assert.ok(directRes.appliedCount >= 5, `Expected >=5 injected FastMCP params, got ${directRes.appliedCount}`);
    // list_orders gets pagination BEFORE **kwargs (valid Python!)
    assert.ok(
      directRes.patched.includes('async def list_orders(customer_id: str, limit: int = 25, cursor: str = "", **kwargs):'),
      'list_orders must receive limit/cursor before **kwargs'
    );
    // charge_card gets idempotency_key
    assert.ok(
      directRes.patched.includes('async def charge_card(amount_cents: int, currency: str = "USD", idempotency_key: str = ""'),
      'async mutation charge_card must receive idempotency_key'
    );
    // delete_workspace gets BOTH idempotency_key and dry_run
    assert.ok(
      directRes.patched.includes('def delete_workspace(workspace_id: str, idempotency_key: str = "", dry_run: bool = False):'),
      'destructive delete_workspace must receive idempotency_key and dry_run'
    );
    // get_health (simple read-only) stays untouched
    assert.ok(
      directRes.patched.includes('def get_health():'),
      'Simple read-only get_health must remain untouched'
    );

    const prevLog = console.log;
    console.log = () => {};
    try {
      await fixCommand(tmpDir, { lang: 'fastmcp', apply: true });
      const writtenPy = fs.readFileSync(serverPy, 'utf-8');
      assert.strictEqual(writtenPy, directRes.patched);
      // Prove patched Python compiles with zero SyntaxError via real Python 3
      assertValidPythonSyntax(serverPy);

      // Idempotency: re-running fix --apply must be a zero-diff no-op
      const secondRun = patchFastMcpPythonSource(writtenPy);
      assert.strictEqual(secondRun.appliedCount, 0, 'Re-running FastMCP patcher must be idempotent');
    } finally {
      console.log = prevLog;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
