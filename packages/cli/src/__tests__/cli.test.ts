import { describe, it, before, after } from 'node:test';
import * as assert from 'node:assert';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import crypto from 'node:crypto';
import http from 'node:http';
import { fixCommand } from '../commands/fix.js';
import { verifyCommand } from '../commands/verify.js';
import { badgeCommand } from '../commands/badge.js';
import { checkCommand } from '../commands/check.js';
import { evidenceCommand } from '../commands/evidence.js';
import { loginCommand } from '../commands/login.js';
import { proxyCommand } from '../commands/proxy.js';

describe('ToolVeto CLI Commands', () => {
  let origLog: typeof console.log;
  let origErr: typeof console.error;

  before(() => {
    origLog = console.log;
    origErr = console.error;
    console.log = () => {};
    console.error = () => {};
  });

  after(() => {
    console.log = origLog;
    console.error = origErr;
  });

  it('should auto-apply idempotency fix to JSON schema files (toolveto fix --apply)', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-fix-test-'));
    const fixturePath = path.join(tmpDir, 'tools.json');

    // Create a vulnerable schema missing idempotency_key
    const vulnerableTools = [
      {
        name: 'transfer_credits',
        description: 'Transfers internal platform credits between users',
        isMutation: true,
        inputSchema: {
          type: 'object',
          properties: {
            recipientId: { type: 'string' },
            credits: { type: 'number' },
          },
          required: ['recipientId', 'credits'],
        },
      },
    ];

    fs.writeFileSync(fixturePath, JSON.stringify(vulnerableTools, null, 2));

    // Run fixCommand with apply: true
    await fixCommand(fixturePath, {
      apply: true,
    });

    // Verify file on disk was modified with idempotency_key
    const fixedContent = JSON.parse(fs.readFileSync(fixturePath, 'utf-8'));
    const fixedTool = fixedContent[0];

    assert.ok(fixedTool.inputSchema.properties.idempotency_key, 'idempotency_key property must be added');
    assert.strictEqual(fixedTool.inputSchema.properties.idempotency_key.type, 'string');
    assert.ok(fixedTool.inputSchema.required.includes('idempotency_key'), 'idempotency_key must be marked required');

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should generate toolveto-remediation.patch when running fix on code repositories', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-patch-test-'));
    const originalCwd = process.cwd();
    process.chdir(tmpDir);

    try {
      await fixCommand(tmpDir, {
        suggest: true,
      });

      const patchFile = path.join(tmpDir, 'toolveto-remediation.patch');
      assert.ok(fs.existsSync(patchFile), 'toolveto-remediation.patch must be generated on disk');
      const patchContent = fs.readFileSync(patchFile, 'utf-8');
      assert.ok(patchContent.includes('diff --git') || patchContent.includes('--- a/'), 'Patch must follow git diff unified format');
      assert.ok(patchContent.includes('idempotencyKey: z.string()'), 'Patch must include Zod idempotency definition');
    } finally {
      process.chdir(originalCwd);
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('should verify cryptographically signed RFC 7515 JWS tokens (toolveto verify)', async () => {
    const secret = 'test-verification-secret-2026-secure-32chars';
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: 'test-key' })).toString('base64url');
    const payload = Buffer.from(
      JSON.stringify({
        sub: 'stripe/agent-toolkit',
        score: 95,
        tier: 'PLATINUM',
        phi: 1.0,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        roi: {
          preventedDoubleCharges: 3,
          estimatedSavingsUsd: 1020,
          tokensSaved: 384000,
        },
      })
    ).toString('base64url');

    const sig = crypto.createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url');
    const validToken = `${header}.${payload}.${sig}`;

    // Verify valid token
    process.exitCode = 0;
    await verifyCommand(validToken, { secret });
    assert.strictEqual(process.exitCode, 0, 'Valid token must exit with code 0');

    // Verify tampered token fails
    const tamperedSig = sig.slice(0, -4) + 'abcd';
    const tamperedToken = `${header}.${payload}.${tamperedSig}`;
    await verifyCommand(tamperedToken, { secret });
    assert.strictEqual(process.exitCode, 1, 'Tampered token must set exit code 1');
    process.exitCode = 0;
  });

  it('should generate SVG badge on disk (toolveto badge)', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-badge-test-'));
    const outputPath = path.join(tmpDir, 'badge.svg');

    await badgeCommand({
      score: 95,
      tier: 'PLATINUM',
      output: outputPath,
    });

    assert.ok(fs.existsSync(outputPath), 'SVG badge file must exist');
    const svg = fs.readFileSync(outputPath, 'utf-8');
    assert.ok(svg.includes('<svg'), 'File must contain SVG element');
    assert.ok(svg.includes('PLATINUM 95/100'), 'SVG must render PLATINUM score text');

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should audit compliant tool manifest and pass (toolveto check)', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-check-good-'));
    const manifestPath = path.join(tmpDir, 'tools.json');

    const compliantTools = [
      {
        name: 'create_invoice',
        description: 'Creates a verified customer invoice with idempotency and limit controls',
        isMutation: true,
        inputSchema: {
          type: 'object',
          properties: {
            customer_id: { type: 'string' },
            idempotency_key: { type: 'string' },
            amount: { type: 'number' },
          },
          required: ['customer_id', 'idempotency_key', 'amount'],
        },
      },
    ];
    fs.writeFileSync(manifestPath, JSON.stringify(compliantTools, null, 2));

    process.exitCode = 0;
    await checkCommand(manifestPath, { json: true });
    assert.strictEqual(process.exitCode, 0, 'Compliant manifest must succeed with exit code 0');

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should trigger fatal veto on destructive mutation without permission (toolveto check)', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-check-destr-'));
    const manifestPath = path.join(tmpDir, 'tools.json');

    const destructiveTools = [
      {
        name: 'drop_database',
        description: 'Deletes all database records permanently without confirmation',
        isMutation: true,
        inputSchema: { type: 'object', properties: {} },
      },
    ];
    fs.writeFileSync(manifestPath, JSON.stringify(destructiveTools, null, 2));

    process.exitCode = 0;
    await checkCommand(manifestPath, { json: true });
    assert.strictEqual(process.exitCode, 1, 'Destructive mutation must trigger exit code 1');
    process.exitCode = 0;

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should enforce high-entropy secret in evidence generation (toolveto evidence)', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-evid-test-'));
    const manifestPath = path.join(tmpDir, 'tools.json');
    fs.writeFileSync(manifestPath, JSON.stringify([{
      name: 'get_status',
      description: 'Reads current system operational status',
      isMutation: false,
      inputSchema: { type: 'object', properties: {} },
    }]));

    // Without secret, evidenceCommand must throw fatal security violation
    const oldSecret = process.env.TOOLVETO_SIGNING_SECRET;
    delete process.env.TOOLVETO_SIGNING_SECRET;

    await assert.rejects(
      async () => {
        await evidenceCommand({ target: manifestPath, format: 'json' });
      },
      /FATAL SECURITY VIOLATION: TOOLVETO_SIGNING_SECRET/
    );

    // With 32+ char secret, evidenceCommand succeeds
    const outputPath = path.join(tmpDir, 'evidence.json');
    await evidenceCommand({
      target: manifestPath,
      format: 'json',
      secret: 'secure-high-entropy-attestation-secret-32chars',
      output: outputPath,
    });
    assert.ok(fs.existsSync(outputPath), 'Evidence output file must be created');
    const content = JSON.parse(fs.readFileSync(outputPath, 'utf-8'));
    assert.ok(content.jws, 'Generated evidence packet must include cryptographic JWS signature');

    if (oldSecret) process.env.TOOLVETO_SIGNING_SECRET = oldSecret;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should authenticate and write credentials to ~/.toolveto/config.json with 0o600 permissions (toolveto login)', async () => {
    const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-home-test-'));
    const oldHome = process.env.HOME;
    process.env.HOME = tmpHome;

    // Start mock cloud API
    const mockApi = http.createServer((req, res) => {
      if (req.method === 'POST' && req.url === '/api/v1/billing/license/validate') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          valid: true,
          tier: 'TEAM',
          customerId: 'cus_cli_login_test',
          expiresAt: new Date(Date.now() + 86400000).toISOString(),
        }));
      } else {
        res.writeHead(404);
        res.end();
      }
    });

    await new Promise<void>((resolve) => mockApi.listen(0, () => resolve()));
    const port = (mockApi.address() as any).port;

    try {
      process.exitCode = 0;
      await loginCommand('tv_live_mock_token_123', { apiUrl: `http://localhost:${port}` });
      assert.strictEqual(process.exitCode, 0);

      const configPath = path.join(tmpHome, '.toolveto', 'config.json');
      assert.ok(fs.existsSync(configPath), 'Config file must be created');
      const stats = fs.statSync(configPath);
      if (process.platform !== 'win32') {
        assert.strictEqual(stats.mode & 0o777, 0o600, 'Config file permissions must be 0o600');
      }

      const configData = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
      assert.strictEqual(configData.token, 'tv_live_mock_token_123');
      assert.strictEqual(configData.tier, 'TEAM');
      assert.strictEqual(configData.customerId, 'cus_cli_login_test');
    } finally {
      process.env.HOME = oldHome;
      await new Promise<void>((resolve) => mockApi.close(() => resolve()));
      fs.rmSync(tmpHome, { recursive: true, force: true });
    }
  });

  it('should set exitCode 1 on rejected license token (toolveto login)', async () => {
    const mockApi = http.createServer((req, res) => {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ valid: false, error: 'Invalid license key' }));
    });

    await new Promise<void>((resolve) => mockApi.listen(0, () => resolve()));
    const port = (mockApi.address() as any).port;

    try {
      process.exitCode = 0;
      await loginCommand('tv_live_bad_token', { apiUrl: `http://localhost:${port}` });
      assert.strictEqual(process.exitCode, 1, 'Rejected license must set process.exitCode = 1');
      process.exitCode = 0;
    } finally {
      await new Promise<void>((resolve) => mockApi.close(() => resolve()));
    }
  });

  it('should initialize and start Shield runtime proxy gateway (toolveto proxy)', async () => {
    const server = await proxyCommand({ port: 0, upstream: 'http://localhost:9999/mcp', tokenBudget: 2000 });
    assert.ok(server, 'Proxy command must return running server');
    const addr = server.address();
    assert.ok(addr && typeof addr === 'object' && addr.port > 0, 'Server must bind to valid port');
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('should enforce --threshold, --fail-on-severity, and audit multi-server .cursor/mcp.json configs (toolveto check)', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-check-multi-'));
    const cursorDir = path.join(tmpDir, '.cursor');
    fs.mkdirSync(cursorDir, { recursive: true });
    const mcpJsonPath = path.join(cursorDir, 'mcp.json');

    fs.writeFileSync(
      mcpJsonPath,
      JSON.stringify({
        mcpServers: {
          billing: {
            tools: [
              {
                name: 'create_invoice',
                description: 'Creates a verified customer invoice with idempotency and limit controls',
                isMutation: true,
                inputSchema: {
                  type: 'object',
                  properties: {
                    customer_id: { type: 'string' },
                    idempotency_key: { type: 'string' },
                    dry_run: { type: 'boolean' },
                  },
                  required: ['customer_id', 'idempotency_key'],
                  additionalProperties: false,
                },
              },
            ],
          },
        },
      })
    );

    // Threshold 101 should fail
    process.exitCode = 0;
    await checkCommand(tmpDir, { json: true, threshold: 101 });
    assert.strictEqual(process.exitCode, 1, 'Threshold 101 must set exit code 1');

    // Fail-on-severity HIGH on unpained mutation (TC-PAIR-001 fails with HIGH)
    process.exitCode = 0;
    await checkCommand(tmpDir, { json: true, failOnSeverity: 'HIGH' });
    assert.strictEqual(process.exitCode, 1, 'failOnSeverity HIGH must set exit code 1 when HIGH check fails');
    process.exitCode = 0;

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should patch .ts, .py, and .go source files on disk when running toolveto fix --apply', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-fix-src-'));
    const tsFile = path.join(tmpDir, 'server.ts');
    const pyFile = path.join(tmpDir, 'server.py');
    const goFile = path.join(tmpDir, 'server.go');

    fs.writeFileSync(
      tsFile,
      `import { z } from 'zod';\nconst schema = z.object({\n  amount: z.number(),\n});\n`
    );
    fs.writeFileSync(
      pyFile,
      `from pydantic import BaseModel\nclass ChargeArgs(BaseModel):\n    amount: float\n`
    );
    fs.writeFileSync(
      goFile,
      `package main\ntype ChargeInput struct {\n\tAmount float64 \`json:"amount"\`\n}\n`
    );

    await fixCommand(tmpDir, { apply: true, check: 'TC-IDEMP-001' });

    const tsUpdated = fs.readFileSync(tsFile, 'utf-8');
    const pyUpdated = fs.readFileSync(pyFile, 'utf-8');
    const goUpdated = fs.readFileSync(goFile, 'utf-8');

    assert.ok(tsUpdated.includes('idempotencyKey'), 'TypeScript file must be patched with idempotencyKey');
    assert.ok(pyUpdated.includes('idempotency_key'), 'Python file must be patched with idempotency_key');
    assert.ok(goUpdated.includes('IdempotencyKey'), 'Go file must be patched with IdempotencyKey');

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should verify ES256 asymmetric JWS tokens and --jws flag (toolveto verify)', async () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const headerB64 = Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'JWT', kid: 'es256-key-1' })).toString('base64url');
    const payloadB64 = Buffer.from(
      JSON.stringify({
        sub: 'es256-server',
        score: 96,
        tier: 'Platinum',
        phi: 1.0,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
      })
    ).toString('base64url');

    const sig = crypto
      .sign('sha256', Buffer.from(`${headerB64}.${payloadB64}`), { key: privateKey, dsaEncoding: 'ieee-p1363' })
      .toString('base64url');
    const jws = `${headerB64}.${payloadB64}.${sig}`;
    const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();

    process.exitCode = 0;
    await verifyCommand(undefined, { jws, publicKey: pubPem });
    assert.strictEqual(process.exitCode, 0, 'Valid ES256 token via --jws must succeed');
  });

  it('should generate toolveto.lock.json and export Cedar/OPA policies (toolveto lock & export-policy)', async () => {
    const { lockCommand } = await import('../commands/lock.js');
    const { exportPolicyCommand } = await import('../commands/export-policy.js');

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-lock-policy-'));
    const toolsPath = path.join(tmpDir, 'tools.json');
    fs.writeFileSync(
      toolsPath,
      JSON.stringify([
        {
          name: 'create_payment',
          description: 'Creates a verified payment with idempotency protection',
          isMutation: true,
          inputSchema: {
            type: 'object',
            properties: {
              amount: { type: 'number' },
              idempotency_key: { type: 'string' },
            },
            required: ['amount', 'idempotency_key'],
          },
        },
      ])
    );

    const lockPath = path.join(tmpDir, 'toolveto.lock.json');
    await lockCommand(toolsPath, { output: lockPath });
    assert.ok(fs.existsSync(lockPath), 'toolveto.lock.json must be created');
    const lockData = JSON.parse(fs.readFileSync(lockPath, 'utf-8'));
    assert.ok(lockData.tools.create_payment?.sha256, 'Lockfile must contain SHA-256 hash of create_payment');

    const cedarPath = path.join(tmpDir, 'policy.cedar');
    await exportPolicyCommand(toolsPath, { format: 'cedar', output: cedarPath });
    assert.ok(fs.existsSync(cedarPath), 'Cedar policy file must be created');
    assert.ok(fs.readFileSync(cedarPath, 'utf-8').includes('Tool::"create_payment"'));

    const opaPath = path.join(tmpDir, 'policy.rego');
    await exportPolicyCommand(toolsPath, { format: 'opa', output: opaPath });
    assert.ok(fs.existsSync(opaPath), 'OPA Rego policy file must be created');
    assert.ok(fs.readFileSync(opaPath, 'utf-8').includes('package toolveto.authz'));

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should wrap and unwrap MCP server configs cleanly via toolveto wrap and toolveto wrap --unwrap', async () => {
    const { wrapCommand } = await import('../commands/wrap.js');
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-wrap-test-'));
    const cursorDir = path.join(tmpDir, '.cursor');
    fs.mkdirSync(cursorDir, { recursive: true });
    const mcpJsonPath = path.join(cursorDir, 'mcp.json');

    const initialConfig = {
      mcpServers: {
        stripe: {
          command: 'npx',
          args: ['-y', '@stripe/mcp', '--tools=all'],
          env: { STRIPE_SECRET_KEY: 'sk_test_123' },
        },
        postgres: {
          command: 'uvx',
          args: ['mcp-server-postgres', 'postgresql://localhost/mydb'],
        },
      },
    };
    fs.writeFileSync(mcpJsonPath, JSON.stringify(initialConfig, null, 2));

    // 1. Wrap servers with --token-budget 3500 and --strict
    const wrapRes = await wrapCommand(mcpJsonPath, { tokenBudget: 3500, strict: true });
    assert.ok(wrapRes, 'wrapCommand must return result');
    assert.deepStrictEqual(wrapRes.wrappedServers, ['stripe', 'postgres']);

    const wrappedOnDisk = JSON.parse(fs.readFileSync(mcpJsonPath, 'utf-8'));
    assert.strictEqual(wrappedOnDisk.mcpServers.stripe.command, 'npx');
    assert.deepStrictEqual(wrappedOnDisk.mcpServers.stripe.args, [
      '-y',
      'toolveto',
      'proxy',
      '--upstream',
      'npx -y @stripe/mcp --tools=all',
      '--token-budget',
      '3500',
      '--strict',
    ]);
    assert.deepStrictEqual(wrappedOnDisk.mcpServers.stripe._toolvetoOriginal, {
      command: 'npx',
      args: ['-y', '@stripe/mcp', '--tools=all'],
    });

    // 2. Re-running wrap skips already wrapped servers
    const wrapAgain = await wrapCommand(mcpJsonPath, { tokenBudget: 3500 });
    assert.deepStrictEqual(wrapAgain?.wrappedServers, []);

    // 3. Unwrap restores exact original commands and removes _toolvetoOriginal
    const unwrapRes = await wrapCommand(mcpJsonPath, { unwrap: true });
    assert.deepStrictEqual(unwrapRes?.unwrappedServers, ['stripe', 'postgres']);

    const restoredOnDisk = JSON.parse(fs.readFileSync(mcpJsonPath, 'utf-8'));
    assert.strictEqual(restoredOnDisk.mcpServers.stripe.command, 'npx');
    assert.deepStrictEqual(restoredOnDisk.mcpServers.stripe.args, ['-y', '@stripe/mcp', '--tools=all']);
    assert.strictEqual(restoredOnDisk.mcpServers.stripe._toolvetoOriginal, undefined);
    assert.strictEqual(restoredOnDisk.mcpServers.postgres.command, 'uvx');
    assert.deepStrictEqual(restoredOnDisk.mcpServers.postgres.args, [
      'mcp-server-postgres',
      'postgresql://localhost/mydb',
    ]);

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should execute dynamic 14-check evaluation with VERIFIED runtime evidence via toolveto check --ephemeral-mock', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-ephemeral-mock-'));
    const manifestPath = path.join(tmpDir, 'tools.json');

    // 1. Vulnerable manifest lacking idempotency_key: --ephemeral-mock dynamically proves duplicate entity creation!
    const vulnerableTools = [
      {
        name: 'charge_customer',
        description: 'Charges customer credit card',
        isMutation: true,
        inputSchema: {
          type: 'object',
          properties: {
            customer_id: { type: 'string' },
            amount: { type: 'number' },
            billing_date: { type: 'string', format: 'date' },
          },
          required: ['customer_id', 'amount'],
          additionalProperties: false,
        },
      },
    ];
    fs.writeFileSync(manifestPath, JSON.stringify(vulnerableTools, null, 2));

    process.exitCode = 0;
    const vulnSummary = await checkCommand(manifestPath, { ephemeralMock: true, json: true });
    assert.ok(vulnSummary, 'checkCommand with --ephemeral-mock must return SuiteSummary');
    const replayCheck = vulnSummary.results.find((r) => r.checkId === 'TC-IDEMP-001');
    const burstCheck = vulnSummary.results.find((r) => r.checkId === 'TC-IDEMP-002');
    const crashCheck = vulnSummary.results.find((r) => r.checkId === 'TC-IDEMP-003');
    const fuzzCheck = vulnSummary.results.find((r) => r.checkId === 'TC-FUZZ-001');

    assert.strictEqual(replayCheck?.status, 'FAIL');
    assert.strictEqual(replayCheck?.evidence?.evidenceQuality, 'VERIFIED');
    assert.strictEqual(replayCheck?.evidence?.mutationsCreated, 5);
    assert.strictEqual(burstCheck?.status, 'FAIL');
    assert.strictEqual(burstCheck?.evidence?.evidenceQuality, 'VERIFIED');
    assert.strictEqual(crashCheck?.status, 'FAIL');
    assert.strictEqual(crashCheck?.evidence?.evidenceQuality, 'VERIFIED');
    assert.strictEqual(fuzzCheck?.status, 'PASS');
    assert.strictEqual(fuzzCheck?.evidence?.evidenceQuality, 'VERIFIED');

    // 2. Compliant manifest with idempotency_key: --ephemeral-mock dynamically deduplicates and passes D1 checks with VERIFIED evidence
    const compliantTools = [
      {
        name: 'charge_customer',
        description: 'Charges customer credit card safely with idempotency protection (Requires OAuth 2.1 scope: write:charges)',
        isMutation: true,
        inputSchema: {
          type: 'object',
          properties: {
            customer_id: { type: 'string', description: 'Unique customer identifier' },
            amount: { type: 'number', description: 'Amount in cents' },
            idempotency_key: { type: 'string', description: 'Unique key for idempotent deduplication' },
            dry_run: { type: 'boolean', description: 'Simulate execution without committing state' },
          },
          required: ['customer_id', 'amount', 'idempotency_key'],
          additionalProperties: false,
        },
      },
      {
        name: 'get_customer_charge',
        description: 'Retrieves charge details by customer_id before or after mutation',
        isMutation: false,
        inputSchema: {
          type: 'object',
          properties: {
            customer_id: { type: 'string', description: 'Unique customer identifier' },
          },
          required: ['customer_id'],
          additionalProperties: false,
        },
      },
    ];
    fs.writeFileSync(manifestPath, JSON.stringify(compliantTools, null, 2));

    process.exitCode = 0;
    const goodSummary = await checkCommand(manifestPath, { ephemeralMock: true, json: true });
    assert.ok(goodSummary);
    const goodReplay = goodSummary.results.find((r) => r.checkId === 'TC-IDEMP-001' && r.tool === 'charge_customer');
    assert.strictEqual(goodReplay?.status, 'PASS');
    assert.strictEqual(goodReplay?.evidence?.evidenceQuality, 'VERIFIED');
    assert.strictEqual(goodReplay?.evidence?.mutationsCreated, 1);

    process.exitCode = 0;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});
