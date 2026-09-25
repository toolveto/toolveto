import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import crypto from 'node:crypto';
import { fixCommand } from '../commands/fix.js';
import { verifyCommand } from '../commands/verify.js';
import { badgeCommand } from '../commands/badge.js';

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
    const secret = 'test-verification-secret-2026';
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
});
