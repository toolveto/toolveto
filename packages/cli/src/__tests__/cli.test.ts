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

  it('should synthesize both Tier-1 Zod schema contracts and Tier-2 handler body guards when --with-llm is passed', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-llm-fix-test-'));
    const originalCwd = process.cwd();
    process.chdir(tmpDir);
    const srcFile = path.join(tmpDir, 'charge.ts');
    fs.writeFileSync(
      srcFile,
      [
        `import { z } from 'zod';`,
        `export const ChargeInput = z.object({`,
        `  amount: z.number(),`,
        `});`,
        `export const chargeHandler = async (args: Record<string, unknown>) => {`,
        `  return { charged: args.amount };`,
        `};`,
      ].join('\n'),
      'utf8'
    );

    try {
      await fixCommand(srcFile, {
        apply: true,
        withLlm: true,
      });

      const updated = fs.readFileSync(srcFile, 'utf8');
      assert.ok(updated.includes('idempotencyKey: z.string().uuid()'), 'Tier-1 schema field must be injected');
      assert.ok(updated.includes('__toolvetoIdempotencyCache'), 'Tier-2 imperative idempotency cache guard must be woven into handler');
      assert.ok(updated.includes('DRY_RUN_VALIDATED'), 'Tier-2 dry_run simulation guard must be woven into handler');
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
          url: 'http://localhost:3000/mcp',
          env: { STRIPE_SECRET_KEY: 'sk_test_123' },
        },
        postgres: {
          url: 'https://postgres.internal.net/mcp',
        },
        localStdio: {
          command: 'npx',
          args: ['-y', '@stdio/mcp'],
        },
      },
    };
    fs.writeFileSync(mcpJsonPath, JSON.stringify(initialConfig, null, 2));

    // 1. Wrap servers with --token-budget 3500 and --strict (skipping stdio)
    const wrapRes = await wrapCommand(mcpJsonPath, { tokenBudget: 3500, strict: true });
    assert.ok(wrapRes, 'wrapCommand must return result');
    assert.deepStrictEqual(wrapRes.wrappedServers, ['stripe', 'postgres']);

    const wrappedOnDisk = JSON.parse(fs.readFileSync(mcpJsonPath, 'utf-8'));
    assert.strictEqual(wrappedOnDisk.mcpServers.localStdio.command, 'npx');
    assert.strictEqual(wrappedOnDisk.mcpServers.localStdio._toolvetoOriginal, undefined);
    assert.strictEqual(wrappedOnDisk.mcpServers.stripe.command, 'npx');
    assert.deepStrictEqual(wrappedOnDisk.mcpServers.stripe.args, [
      '-y',
      'toolveto',
      'proxy',
      '--upstream',
      'http://localhost:3000/mcp',
      '--token-budget',
      '3500',
      '--strict',
    ]);
    assert.deepStrictEqual(wrappedOnDisk.mcpServers.stripe._toolvetoOriginal, {
      command: '',
      args: [],
    });

    // 2. Re-running wrap skips already wrapped servers
    const wrapAgain = await wrapCommand(mcpJsonPath, { tokenBudget: 3500 });
    assert.deepStrictEqual(wrapAgain?.wrappedServers, []);

    // 3. Unwrap restores exact original commands and removes _toolvetoOriginal
    const unwrapRes = await wrapCommand(mcpJsonPath, { unwrap: true });
    assert.deepStrictEqual(unwrapRes?.unwrappedServers, ['stripe', 'postgres']);

    const restoredOnDisk = JSON.parse(fs.readFileSync(mcpJsonPath, 'utf-8'));
    assert.strictEqual(restoredOnDisk.mcpServers.stripe.command, '');
    assert.deepStrictEqual(restoredOnDisk.mcpServers.stripe.args, []);
    assert.strictEqual(restoredOnDisk.mcpServers.stripe._toolvetoOriginal, undefined);
    assert.strictEqual(restoredOnDisk.mcpServers.stripe.url, 'http://localhost:3000/mcp');

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

  it('should execute Trivy/Grype-style update checker, capture anonymous PLG run telemetry, and respect DO_NOT_TRACK opt-out', async () => {
    const {
      runPlgTelemetryAndUpdateCheck,
      getOrCreateCliState,
      isTelemetryDisabled,
      isUpdateCheckDisabled,
      formatTrivyStyleNotice,
    } = await import('../telemetry.js');

    const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-plg-home-'));
    const oldHome = process.env.HOME;
    const oldDnt = process.env.DO_NOT_TRACK;
    const outerGhActions = process.env.GITHUB_ACTIONS;
    const outerGhRepo = process.env.GITHUB_REPOSITORY;
    const outerGhRunNum = process.env.GITHUB_RUN_NUMBER;
    const outerCi = process.env.CI;
    process.env.HOME = tmpHome;
    delete process.env.DO_NOT_TRACK;
    delete process.env.GITHUB_ACTIONS;
    delete process.env.GITHUB_REPOSITORY;
    delete process.env.GITHUB_RUN_NUMBER;
    delete process.env.CI;

    const telemetryPayloads: any[] = [];
    let versionCheckRequests = 0;

    const mockApi = http.createServer((req, res) => {
      if (req.method === 'GET' && req.url?.startsWith('/api/v1/cli/version-check')) {
        versionCheckRequests++;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            latestVersion: '0.3.0',
            latestCorpusVersion: 'v1.1',
            sealedCorpusChecksCount: 14,
            releaseUrl: 'https://github.com/toolveto/toolveto/releases/tag/v0.3.0',
            upgradeCommand: 'npm i -g toolveto@latest',
          })
        );
      } else if (req.method === 'POST' && req.url === '/api/v1/cli/telemetry') {
        let body = '';
        req.on('data', (c) => (body += c));
        req.on('end', () => {
          telemetryPayloads.push(JSON.parse(body));
          res.writeHead(201, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true }));
        });
      } else {
        res.writeHead(404);
        res.end();
      }
    });

    await new Promise<void>((resolve) => mockApi.listen(0, () => resolve()));
    const port = (mockApi.address() as any).port;

    const mockSummary: any = {
      score: 52,
      tier: 'Rejected',
      fatalVetoTriggered: true,
      fatalVetoes: ['VETO_IDEMP'],
      phiMultiplier: 0.7,
      dimensionScores: {},
      results: [
        { checkId: 'TC-IDEMP-001', status: 'FAIL', severity: 'CRITICAL', tool: 'charge', message: 'Missing idempotency' },
        { checkId: 'TC-IDEMP-002', status: 'FAIL', severity: 'HIGH', tool: 'charge', message: 'Burst duplicate' },
        { checkId: 'TC-SEC-002', status: 'PASS', severity: 'CRITICAL', tool: 'charge', message: 'Clean' },
      ],
    };

    try {
      // 1. Run PLG telemetry + version check against mock server
      const result = await runPlgTelemetryAndUpdateCheck({
        summary: mockSummary,
        target: '/workspace/stripe-mcp',
        durationMs: 42,
        options: {
          customHomeDir: tmpHome,
          apiUrl: `http://localhost:${port}`,
        },
      });

      assert.strictEqual(result.telemetrySent, true, 'Anonymous PLG telemetry must be sent');
      assert.strictEqual(result.payload?.runNumber, 1, 'Local run counter must increment to 1');
      assert.strictEqual(telemetryPayloads.length, 1);
      assert.strictEqual(telemetryPayloads[0].score, 52);
      assert.strictEqual(telemetryPayloads[0].tier, 'Rejected');
      assert.strictEqual(telemetryPayloads[0].fatalVetoTriggered, true);
      assert.deepStrictEqual(telemetryPayloads[0].failedCheckIds, ['TC-IDEMP-001', 'TC-IDEMP-002']);
      assert.ok(telemetryPayloads[0].targetHash.startsWith('sha256_'), 'Target path must be SHA-256 anonymized');
      assert.ok(!telemetryPayloads[0].targetHash.includes('stripe-mcp'), 'Raw repo path must never be leaked');

      assert.strictEqual(versionCheckRequests, 1);
      assert.strictEqual(result.updateAvailable, true);
      assert.strictEqual(result.latestVersion, '0.3.0');
      assert.ok(result.noticeText?.includes('v0.2.0 → v0.3.0'));

      // 2. Verify ~/.toolveto/cli-state.json persistence
      const { state: persistedState } = getOrCreateCliState(tmpHome);
      assert.strictEqual(persistedState.totalRuns, 1);
      assert.strictEqual(persistedState.latestKnownVersion, '0.3.0');

      // 3. Verify Trivy/Grype notice box formatting
      const formatted = formatTrivyStyleNotice({
        currentVersion: '0.2.0',
        latestVersion: '0.3.0',
        latestCorpusVersion: 'v1.1',
        summary: mockSummary,
        authenticated: false,
        runNumber: 1,
      });
      assert.ok(formatted.includes('v0.2.0 → v0.3.0'), 'Must display version upgrade notice like Trivy/Grype');
      assert.ok(formatted.includes('PLG Security Advisory'), 'Must display contextual PLG remediation advisory');
      assert.ok(formatted.includes('DO_NOT_TRACK=1'), 'Must display standard opt-out env vars');

      // 4. Verify DO_NOT_TRACK=1, TOOLVETO_NO_TELEMETRY=1, and TOOLVETO_TELEMETRY_DISABLED=1 opt-outs disable telemetry
      process.env.DO_NOT_TRACK = '1';
      assert.strictEqual(isTelemetryDisabled(), true);
      delete process.env.DO_NOT_TRACK;
      process.env.TOOLVETO_NO_TELEMETRY = '1';
      assert.strictEqual(isTelemetryDisabled(), true);
      delete process.env.TOOLVETO_NO_TELEMETRY;
      process.env.TOOLVETO_TELEMETRY_DISABLED = '1';
      assert.strictEqual(isTelemetryDisabled(), true);
      delete process.env.TOOLVETO_TELEMETRY_DISABLED;
      assert.strictEqual(isTelemetryDisabled({ noTelemetry: true }), true);
      assert.strictEqual(isUpdateCheckDisabled({ skipUpdateCheck: true }), true);

      // 4b. Verify offline/network failure resilience never throws
      const offlineRes = await runPlgTelemetryAndUpdateCheck({
        summary: mockSummary,
        target: '/workspace/stripe-mcp',
        durationMs: 15,
        options: {
          customHomeDir: tmpHome,
          apiUrl: 'http://127.0.0.1:1',
        },
      });
      assert.strictEqual(offlineRes.telemetrySent, false, 'Offline telemetry call must gracefully return telemetrySent: false');

      // 5. Verify ephemeral CI containers derive deterministic installId & runNumber across wiped home dirs
      delete process.env.DO_NOT_TRACK;
      const oldGhActions = process.env.GITHUB_ACTIONS;
      const oldGhRepo = process.env.GITHUB_REPOSITORY;
      const oldGhRunNum = process.env.GITHUB_RUN_NUMBER;
      process.env.GITHUB_ACTIONS = 'true';
      process.env.GITHUB_REPOSITORY = 'acme-corp/payments-mcp';
      process.env.GITHUB_RUN_NUMBER = '42';

      const containerHome1 = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-ci-container-1-'));
      const containerHome2 = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-ci-container-2-'));
      try {
        const state1 = getOrCreateCliState(containerHome1).state;
        const state2 = getOrCreateCliState(containerHome2).state;
        assert.ok(state1.installId.startsWith('tv_ci_'), 'CI container must use deterministic tv_ci_ prefix');
        assert.strictEqual(
          state1.installId,
          state2.installId,
          'Two separate ephemeral CI containers for the same repo must produce the exact same installId'
        );
        assert.strictEqual(state1.totalRuns + 1, 42, 'CI container runNumber must seed from GITHUB_RUN_NUMBER (42)');
      } finally {
        if (oldGhActions === undefined) delete process.env.GITHUB_ACTIONS;
        else process.env.GITHUB_ACTIONS = oldGhActions;
        if (oldGhRepo === undefined) delete process.env.GITHUB_REPOSITORY;
        else process.env.GITHUB_REPOSITORY = oldGhRepo;
        if (oldGhRunNum === undefined) delete process.env.GITHUB_RUN_NUMBER;
        else process.env.GITHUB_RUN_NUMBER = oldGhRunNum;
        fs.rmSync(containerHome1, { recursive: true, force: true });
        fs.rmSync(containerHome2, { recursive: true, force: true });
      }
    } finally {
      if (oldDnt === undefined) delete process.env.DO_NOT_TRACK;
      else process.env.DO_NOT_TRACK = oldDnt;
      if (outerGhActions === undefined) delete process.env.GITHUB_ACTIONS;
      else process.env.GITHUB_ACTIONS = outerGhActions;
      if (outerGhRepo === undefined) delete process.env.GITHUB_REPOSITORY;
      else process.env.GITHUB_REPOSITORY = outerGhRepo;
      if (outerGhRunNum === undefined) delete process.env.GITHUB_RUN_NUMBER;
      else process.env.GITHUB_RUN_NUMBER = outerGhRunNum;
      if (outerCi === undefined) delete process.env.CI;
      else process.env.CI = outerCi;
      delete process.env.TOOLVETO_TELEMETRY_DISABLED;
      process.env.HOME = oldHome;
      await new Promise<void>((resolve) => mockApi.close(() => resolve()));
      fs.rmSync(tmpHome, { recursive: true, force: true });
    }
  });

  it('should create a .bak backup before mutating config in toolveto wrap and block path traversal entrypoints in toolveto check', async () => {
    const { wrapCommand } = await import('../commands/wrap.js');
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-sec-wrap-'));
    const mcpJsonPath = path.join(tmpDir, 'mcp.json');
    fs.writeFileSync(
      mcpJsonPath,
      JSON.stringify({
        mcpServers: {
          demo: { command: 'npx', args: ['-y', '@demo/mcp'] },
        },
      })
    );

    await wrapCommand(mcpJsonPath, { tokenBudget: 2000 });
    assert.ok(fs.existsSync(`${mcpJsonPath}.bak`), 'wrapCommand must create a .bak backup file');

    // Path traversal entrypoint in package.json must be rejected
    const traverseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-traverse-'));
    const outsideScript = path.join(tmpDir, 'outside-evil.js');
    fs.writeFileSync(outsideScript, 'console.log("pwned");');
    fs.writeFileSync(
      path.join(traverseDir, 'package.json'),
      JSON.stringify({
        name: 'evil-pkg',
        main: path.relative(traverseDir, outsideScript),
      })
    );

    process.exitCode = 0;
    const summary = await checkCommand(traverseDir, { json: true, allowExec: true });
    assert.strictEqual(summary, undefined, 'Path-traversal package.json entrypoint must not be executed');
    process.exitCode = 0;

    fs.rmSync(tmpDir, { recursive: true, force: true });
    fs.rmSync(traverseDir, { recursive: true, force: true });
  });

  it('should audit IDE configs for floating @latest packages and plaintext secrets and remediate via toolveto doctor --fix', async () => {
    const { doctorCommand } = await import('../commands/doctor.js');
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-doctor-test-'));
    const cursorDir = path.join(tmpDir, '.cursor');
    fs.mkdirSync(cursorDir, { recursive: true });
    const mcpJsonPath = path.join(cursorDir, 'mcp.json');

    fs.writeFileSync(
      mcpJsonPath,
      JSON.stringify(
        {
          mcpServers: {
            github: {
              command: 'npx',
              args: ['-y', '@modelcontextprotocol/server-github@latest'],
              env: {
                GITHUB_PERSONAL_ACCESS_TOKEN: ['ghp', '1234567890abcdefghijklmnopqrstuv'].join('_'),
              },
            },
          },
        },
        null,
        2
      )
    );

    process.exitCode = 0;
    const reportBefore = await doctorCommand(mcpJsonPath, { json: true });
    assert.ok(reportBefore, 'doctorCommand must return report');
    assert.strictEqual(process.exitCode, 1, 'High/Critical IDE findings must set exitCode 1');
    assert.ok(reportBefore.findings.some((f) => f.category === 'FLOATING_PACKAGE'));
    assert.ok(reportBefore.findings.some((f) => f.category === 'PLAINTEXT_SECRET'));

    process.exitCode = 0;
    const reportFixed = await doctorCommand(mcpJsonPath, { fix: true, json: true });
    assert.ok(reportFixed, 'doctorCommand --fix must return report');
    assert.strictEqual(reportFixed.fixedCount, 2, 'Both floating package and plaintext secret must be fixed');

    const fixedConfig = JSON.parse(fs.readFileSync(mcpJsonPath, 'utf-8'));
    assert.strictEqual(
      fixedConfig.mcpServers.github.args[1],
      '@modelcontextprotocol/server-github@1.0.0',
      '@latest must be pinned to deterministic semver'
    );
    assert.strictEqual(
      fixedConfig.mcpServers.github.env.GITHUB_PERSONAL_ACCESS_TOKEN,
      '${ENV:GITHUB_PERSONAL_ACCESS_TOKEN}',
      'Plaintext secret must be replaced with env var reference'
    );
    assert.ok(fs.existsSync(path.join(cursorDir, 'toolveto-ide.lock.json')), 'toolveto-ide.lock.json must be emitted');

    process.exitCode = 0;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should patch Python @mcp.tool() function signatures and export WeaveProof Genome SHA-256 manifests', async () => {
    const { exportPolicyCommand } = await import('../commands/export-policy.js');
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-py-wp-test-'));
    const pyFile = path.join(tmpDir, 'fastmcp_server.py');

    fs.writeFileSync(
      pyFile,
      `@mcp.tool()\ndef charge_invoice(amount_cents: int):\n    return {"status": "ok"}\n`,
      'utf-8'
    );

    await fixCommand(tmpDir, { apply: true, lang: 'python', withLlm: true });
    const patchedPy = fs.readFileSync(pyFile, 'utf-8');
    assert.ok(patchedPy.includes('idempotency_key: str = ""'), 'FastMCP @mcp.tool() signature must be patched');
    assert.ok(patchedPy.includes('_TOOLVETO_IDEMPOTENCY_CACHE'), 'Python Tier-2 handler guard must be woven');

    const toolsJsonPath = path.join(tmpDir, 'tools.json');
    fs.writeFileSync(
      toolsJsonPath,
      JSON.stringify([
        {
          name: 'charge_invoice',
          description: 'Charges an invoice safely with idempotency key',
          isMutation: true,
          inputSchema: {
            type: 'object',
            properties: { amount_cents: { type: 'number' }, idempotency_key: { type: 'string' } },
          },
        },
      ])
    );

    const genomeOut = path.join(tmpDir, 'weaveproof.genome.json');
    await exportPolicyCommand(toolsJsonPath, { format: 'weaveproof-genome', output: genomeOut });
    assert.ok(fs.existsSync(genomeOut), 'WeaveProof Genome manifest must be written');
    const genomeData = JSON.parse(fs.readFileSync(genomeOut, 'utf-8'));
    assert.strictEqual(genomeData.schemaVersion, 'weaveproof-genome/v1');
    assert.strictEqual(genomeData.pinnedTools[0].toolName, 'charge_invoice');
    assert.ok(genomeData.pinnedTools[0].canonicalSha256.startsWith('sha256:'));
    assert.strictEqual(genomeData.pinnedTools[0].failureCodeOnMismatch, -32004);

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});

