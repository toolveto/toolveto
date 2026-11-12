import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export interface VerifyCommandOptions {
  secret?: string;
  file?: string;
  jws?: string;
  publicKey?: string;
  apiUrl?: string;
}

function resolveEs256PublicKey(rawOrPath?: string): crypto.KeyObject | null {
  let raw = rawOrPath || process.env.TOOLVETO_PUBLIC_KEY;
  if (!raw) {
    const defaultKeypairPath = path.join(os.homedir(), '.toolveto', 'keys', 'es256_keypair.json');
    if (fs.existsSync(defaultKeypairPath)) {
      raw = fs.readFileSync(defaultKeypairPath, 'utf8');
    }
  }
  if (!raw) return null;

  if (fs.existsSync(raw) && fs.statSync(raw).isFile()) {
    raw = fs.readFileSync(raw, 'utf8');
  }

  const trimmed = raw.trim();
  if (trimmed.startsWith('{')) {
    const parsed = JSON.parse(trimmed);
    if (parsed.publicKey && typeof parsed.publicKey === 'string') {
      return crypto.createPublicKey(parsed.publicKey);
    }
    if (parsed.publicKey && typeof parsed.publicKey === 'object') {
      return crypto.createPublicKey({ key: parsed.publicKey, format: 'jwk' });
    }
    if (Array.isArray(parsed.keys) && parsed.keys[0]) {
      return crypto.createPublicKey({ key: parsed.keys[0], format: 'jwk' });
    }
    return crypto.createPublicKey({ key: parsed, format: 'jwk' });
  }

  return crypto.createPublicKey(trimmed);
}

async function fetchEs256PublicKeyFromJwks(kid?: string, explicitApiUrl?: string): Promise<crypto.KeyObject | null> {
  let apiUrl = explicitApiUrl || process.env.TOOLVETO_API_URL || '';
  if (!apiUrl) {
    try {
      const cfgPath = path.join(os.homedir(), '.toolveto', 'config.json');
      if (fs.existsSync(cfgPath)) {
        const saved = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
        if (typeof saved?.apiUrl === 'string' && saved.apiUrl.trim()) {
          apiUrl = saved.apiUrl.trim();
        }
      }
    } catch {
      // ignore
    }
  }
  if (!apiUrl) return null;

  try {
    const jwksUrl = `${apiUrl.replace(/\/+$/, '')}/api/v1/jwks`;
    const res = await fetch(jwksUrl, { signal: AbortSignal.timeout(4000) });
    if (!res.ok) return null;
    const jwks = (await res.json()) as { keys?: Array<Record<string, any>> };
    if (!Array.isArray(jwks.keys) || jwks.keys.length === 0) return null;

    const matched =
      (kid ? jwks.keys.find((k) => k.kid === kid && k.kty === 'EC') : undefined) ||
      jwks.keys.find((k) => k.kty === 'EC');
    if (!matched) return null;
    return crypto.createPublicKey({ key: matched as any, format: 'jwk' });
  } catch {
    return null;
  }
}

export async function verifyCommand(tokenArg?: string, options: VerifyCommandOptions = {}): Promise<void> {
  let token = tokenArg || options.jws;

  if (!token && options.file && fs.existsSync(options.file)) {
    const raw = fs.readFileSync(options.file, 'utf8');
    const match = raw.match(/(?:tv_(?:live|ent)_)?eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/);
    if (match) token = match[0];
  }

  if (!token) {
    console.error('\n❌ Error: Please provide an RFC 7515 JWS attestation token.');
    console.error('Usage: toolveto verify <jws_token>\n');
    process.exitCode = 1;
    return;
  }

  const rawToken = token.trim().replace(/^tv_(?:live|ent)_/, '');
  const parts = rawToken.split('.');
  if (parts.length !== 3) {
    console.error('\n❌ Malformed JWS token: expected 3 base64url segments separated by dots.\n');
    process.exitCode = 1;
    return;
  }

  const [headerB64, payloadB64, signature] = parts;

  try {
    const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    let isValidSignature = false;

    if (header.alg === 'ES256') {
      let pubKey = resolveEs256PublicKey(options.publicKey);
      if (!pubKey) {
        pubKey = await fetchEs256PublicKeyFromJwks(header.kid, options.apiUrl);
      }
      if (!pubKey) {
        console.error(
          '\n❌ Error: ES256 token requires --public-key, --api-url <cloud-url>, TOOLVETO_PUBLIC_KEY, or ~/.toolveto/keys/es256_keypair.json.'
        );
        process.exitCode = 1;
        return;
      }
      const signingInput = Buffer.from(`${headerB64}.${payloadB64}`);
      const sigBytes = Buffer.from(signature, 'base64url');
      isValidSignature =
        crypto.verify('sha256', signingInput, { key: pubKey, dsaEncoding: 'ieee-p1363' }, sigBytes) ||
        crypto.verify('sha256', signingInput, pubKey, sigBytes);
    } else {
      const resolvedSecret = options.secret || process.env.TOOLVETO_SIGNING_SECRET;
      if (!resolvedSecret || resolvedSecret.length < 32) {
        console.error('\n❌ Error: TOOLVETO_SIGNING_SECRET environment variable or --secret option (>=32 chars) is required.');
        process.exitCode = 1;
        return;
      }

      const expectedHmac = crypto.createHmac('sha256', resolvedSecret);
      expectedHmac.update(`${headerB64}.${payloadB64}`);
      const expectedSig = expectedHmac.digest('base64url');

      const sigBuf = Buffer.from(signature);
      const expBuf = Buffer.from(expectedSig);
      isValidSignature = sigBuf.length === expBuf.length && crypto.timingSafeEqual(sigBuf, expBuf);
    }

    const nowSec = Math.floor(Date.now() / 1000);
    const expSec =
      typeof payload.exp === 'number'
        ? payload.exp > 1e11
          ? Math.floor(payload.exp / 1000)
          : payload.exp
        : undefined;
    const iatSec =
      typeof payload.iat === 'number'
        ? payload.iat > 1e11
          ? Math.floor(payload.iat / 1000)
          : payload.iat
        : nowSec;
    const isExpired = expSec !== undefined && nowSec > expSec;

    console.log(`\n================================================================================`);
    console.log(`         TOOLVETO RFC 7515 ATTESTATION VERIFICATION`);
    console.log(`================================================================================`);

    if (isValidSignature && !isExpired) {
      console.log(`\n✅ STATUS: CRYPTOGRAPHICALLY VALID & COMPLIANT`);
    } else if (!isValidSignature) {
      console.log(`\n❌ STATUS: SIGNATURE MISMATCH (UNAUTHORIZED / TAMPERED)`);
    } else {
      console.log(`\n⚠️ STATUS: TOKEN EXPIRED`);
    }

    console.log(`\nTarget / Subject:       ${payload.sub || payload.repo || 'unknown'}`);
    console.log(`Issuer:                 ${payload.iss || 'toolveto-evidence-engine'}`);
    console.log(`Algorithm:              ${header.alg || 'HS256'} (Key ID: ${header.kid || 'default'})`);
    console.log(`Evaluated Score:        ${payload.score ?? 'N/A'}/100 [ Tier: ${payload.tier || 'N/A'} ]`);
    console.log(`Fatal Veto Multiplier:  Φ = ${payload.phi != null ? payload.phi : 1.0}`);
    console.log(`Issued At:              ${new Date(iatSec * 1000).toISOString()}`);
    console.log(`Expires At:             ${expSec ? new Date(expSec * 1000).toISOString() : 'Never'}`);

    if (payload.controls && typeof payload.controls === 'object') {
      console.log(`\n--- AIUC-1 & OWASP CONTROL EVIDENCE ---`);
      for (const [controlId, ctrl] of Object.entries(payload.controls as Record<string, any>)) {
        const symbol =
          ctrl.status === 'COMPLIANT' ? '✅' : ctrl.status === 'NOT_APPLICABLE' ? '➖' : '❌';
        console.log(`  ${symbol} [${controlId}] ${ctrl.title || ''}`);
      }
    }

    if (payload.roi && typeof payload.roi === 'object') {
      console.log(`\n--- RISK & FINANCIAL QUANTIFICATION ---`);
      console.log(`  • Prevented Double-Charges: ${payload.roi.preventedDoubleCharges || 0}`);
      console.log(`  • Estimated Loss Prevented: $${(payload.roi.estimatedSavingsUsd || 0).toLocaleString()} USD`);
      console.log(`  • Context Tokens Shielded:  ${(payload.roi.tokensSaved || 0).toLocaleString()} tokens`);
    }

    console.log(`================================================================================\n`);

    if (!isValidSignature || isExpired) {
      process.exitCode = 1;
    }
  } catch (err: any) {
    console.error(`\n❌ Verification Failed: ${err.message}\n`);
    process.exitCode = 1;
  }
}
