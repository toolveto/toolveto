import { describe, it } from 'node:test';
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
});
