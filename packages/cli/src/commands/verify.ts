import crypto from 'node:crypto';
import dns from 'node:dns';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { readStoredCloudConfig } from '../telemetry.js';

export interface VerifyCommandOptions {
  secret?: string;
  file?: string;
  jws?: string;
  publicKey?: string;
  apiUrl?: string;
  allowNoExp?: boolean;
}

function resolveEs256PublicKey(rawOrPath?: string, expectedKid?: string): crypto.KeyObject | null {
  let raw = rawOrPath || process.env.TOOLVETO_PUBLIC_KEY || process.env.TOOLVETO_ES256_PUBLIC_KEY;
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
    if (expectedKid && typeof parsed.kid === 'string' && parsed.kid !== expectedKid) {
      return null;
    }
    if (typeof parsed.publicKeyPem === 'string') {
      return crypto.createPublicKey(parsed.publicKeyPem);
    }
    if (parsed.publicKey && typeof parsed.publicKey === 'string') {
      return crypto.createPublicKey(parsed.publicKey);
    }
    if (parsed.publicKey && typeof parsed.publicKey === 'object') {
      if (expectedKid && typeof parsed.publicKey.kid === 'string' && parsed.publicKey.kid !== expectedKid) {
        return null;
      }
      return crypto.createPublicKey({ key: parsed.publicKey, format: 'jwk' });
    }
    if (parsed.jwk && typeof parsed.jwk === 'object') {
      if (expectedKid && typeof parsed.jwk.kid === 'string' && parsed.jwk.kid !== expectedKid) {
        return null;
      }
      return crypto.createPublicKey({ key: parsed.jwk, format: 'jwk' });
    }
    if (Array.isArray(parsed.keys)) {
      const matched = expectedKid
        ? parsed.keys.find((k: any) => k && k.kid === expectedKid && (!k.kty || k.kty === 'EC'))
        : parsed.keys.find((k: any) => k && (!k.kty || k.kty === 'EC'));
      if (!matched) return null;
      return crypto.createPublicKey({ key: matched, format: 'jwk' });
    }
    return crypto.createPublicKey({ key: parsed, format: 'jwk' });
  }

  return crypto.createPublicKey(trimmed);
}

function expandIpv6Hextets(ip: string): number[] | null {
  let working = ip.toLowerCase().trim().replace(/^\[|\]$/g, '').split('%')[0];
  if (working.includes('.')) {
    const lastColon = working.lastIndexOf(':');
    const v4 = working.slice(lastColon + 1).split('.').map(Number);
    if (v4.length !== 4 || v4.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
    working = `${working.slice(0, lastColon)}:${((v4[0] << 8) | v4[1]).toString(16)}:${((v4[2] << 8) | v4[3]).toString(16)}`;
  }
  const parts = working.split('::');
  if (parts.length > 2) return null;
  const head = parts[0] ? parts[0].split(':') : [];
  const tail = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
  const missing = 8 - (head.length + tail.length);
  if (missing < 0) return null;
  const hextets = [...head, ...Array(missing).fill('0'), ...tail].map((seg) => parseInt(seg || '0', 16));
  if (hextets.length !== 8 || hextets.some((n) => !Number.isInteger(n) || n < 0 || n > 0xffff)) return null;
  return hextets;
}

function isAllowedJwksIp(rawIp: string): boolean {
  const host = rawIp.toLowerCase().trim().replace(/^\[|\]$/g, '').split('%')[0].replace(/\.+$/, '');
  const ipVer = net.isIP(host);
  if (ipVer === 4) {
    const [a, b] = host.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 192 && b === 168) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 198 && (b === 18 || b === 19)) return false;
    if (a >= 224) return false;
    return true;
  }
  if (ipVer === 6) {
    const h = expandIpv6Hextets(host);
    if (!h) return false;
    if ((h[0] & 0xe000) !== 0x2000) return false;
    if (h[0] === 0x2002) return false;
    if (h[0] === 0x2001 && (h[1] === 0x0000 || h[1] === 0x0002 || h[1] === 0x0db8)) return false;
    if (h[0] === 0x3ffe || (h[0] === 0x3fff && (h[1] & 0xf000) === 0x0000)) return false;
    return true;
  }
  return false;
}

function isAllowedJwksBaseUrl(baseUrl: string): boolean {
  try {
    const parsed = new URL(baseUrl);
    if (parsed.username || parsed.password) return false;
    const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '').split('%')[0].replace(/\.+$/, '');
    const isLoopback = host === 'localhost' || host === '127.0.0.1' || host === '::1';
    if (parsed.protocol === 'http:') {
      return isLoopback;
    }
    if (parsed.protocol !== 'https:') {
      return false;
    }
    if (isLoopback) return true;
    if (
      !host ||
      host === '0.0.0.0' ||
      host === '169.254.169.254' ||
      host === 'metadata.google.internal' ||
      host.endsWith('.localhost') ||
      host.endsWith('.internal') ||
      host.endsWith('.local')
    ) {
      return false;
    }
    if (net.isIP(host) !== 0) {
      return isAllowedJwksIp(host);
    }
    return true;
  } catch {
    return false;
  }
}

async function pinnedJsonRequest(
  parsedUrl: URL,
  method: 'GET' | 'POST',
  pinned: { address: string; family: number } | null,
  headers: Record<string, string>,
  payload: unknown | undefined,
  timeoutMs: number
): Promise<{ ok: boolean; status: number; text: () => Promise<string>; json: () => Promise<any> }> {
  const mod = parsedUrl.protocol === 'http:' ? http : https;
  const bodyStr = payload !== undefined ? JSON.stringify(payload) : undefined;
  return new Promise((resolve, reject) => {
    const req = mod.request(
      parsedUrl,
      {
        method,
        headers: bodyStr !== undefined ? { ...headers, 'Content-Length': String(Buffer.byteLength(bodyStr, 'utf8')) } : headers,
        timeout: timeoutMs,
        ...(pinned
          ? {
              lookup: (_host: string, optsOrCb: any, maybeCb?: any) => {
                const cb = typeof optsOrCb === 'function' ? optsOrCb : maybeCb;
                const opts = typeof optsOrCb === 'object' && optsOrCb !== null ? optsOrCb : {};
                if (typeof cb !== 'function') return;
                if (opts.all) {
                  process.nextTick(() => cb(null, [{ address: pinned.address, family: pinned.family }]));
                } else {
                  process.nextTick(() => cb(null, pinned.address, pinned.family));
                }
              },
              ...(parsedUrl.protocol === 'https:'
                ? { servername: parsedUrl.hostname.replace(/^\[|\]$/g, '').replace(/\.+$/, '') }
                : {}),
            }
          : {}),
      },
      (res) => {
        const status = res.statusCode || 0;
        if (status >= 300 && status < 400) {
          res.resume();
          reject(new Error(`[ToolVeto Security] HTTP redirect (${status}) blocked.`));
          return;
        }
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
        res.on('end', () => {
          const textVal = Buffer.concat(chunks).toString('utf8');
          resolve({
            ok: status >= 200 && status < 300,
            status,
            text: async () => textVal,
            json: async () => JSON.parse(textVal),
          });
        });
      }
    );
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('Request timeout')));
    if (bodyStr !== undefined) req.end(bodyStr);
    else req.end();
  });
}

export async function fetchEs256PublicKeyFromJwks(
  kid?: string,
  explicitApiUrl?: string
): Promise<crypto.KeyObject | null> {
  const storedConfig = readStoredCloudConfig();
  const baseUrl = (
    explicitApiUrl ||
    process.env.TOOLVETO_API_URL ||
    storedConfig.apiUrl ||
    'https://toolveto.ai'
  ).replace(/\/+$/, '');

  if (!isAllowedJwksBaseUrl(baseUrl)) {
    return null;
  }

  const parsedBase = new URL(baseUrl);
  const cleanHost = parsedBase.hostname.toLowerCase().replace(/^\[|\]$/g, '').split('%')[0].replace(/\.+$/, '');
  const isLoopback = cleanHost === 'localhost' || cleanHost === '127.0.0.1' || cleanHost === '::1';
  let pinned: { address: string; family: number } | null = null;
  if (!isLoopback && net.isIP(cleanHost) === 0) {
    const records = await dns.promises.lookup(cleanHost, { all: true }).catch(() => []);
    if (!records.length || records.some((r) => !isAllowedJwksIp(r.address))) {
      return null;
    }
    pinned = { address: records[0].address, family: records[0].family };
  }

  const candidateUrls = [`${baseUrl}/.well-known/jwks.json`, `${baseUrl}/api/v1/jwks`];

  for (const jwksUrl of candidateUrls) {
    try {
      const res = await pinnedJsonRequest(new URL(jwksUrl), 'GET', pinned, {}, undefined, 4000);
      if (!res.ok) continue;
      const jwks = (await res.json()) as { keys?: Array<Record<string, any>> };
      if (!Array.isArray(jwks.keys) || jwks.keys.length === 0) continue;

      const matched = kid
        ? jwks.keys.find((k) => k.kid === kid && k.kty === 'EC')
        : jwks.keys.find((k) => k.kty === 'EC');
      if (!matched) continue;
      return crypto.createPublicKey({ key: matched as any, format: 'jwk' });
    } catch {
      // Try next JWKS endpoint
    }
  }

  return null;
}

function verifyCertificateWrapperClaims(rawFileContent: string, payload: Record<string, any>): string | null {
  const trimmed = rawFileContent.trim();
  if (!trimmed) return null;

  if (trimmed.startsWith('{')) {
    try {
      const wrapper = JSON.parse(trimmed) as Record<string, any>;
      if (wrapper.score !== undefined && Number(wrapper.score) !== Number(payload.score)) {
        return `JSON wrapper score (${wrapper.score}) does not match signed JWS payload score (${payload.score})`;
      }
      if (
        typeof wrapper.tier === 'string' &&
        typeof payload.tier === 'string' &&
        wrapper.tier.trim().toUpperCase() !== payload.tier.trim().toUpperCase()
      ) {
        return `JSON wrapper tier (${wrapper.tier}) does not match signed JWS payload tier (${payload.tier})`;
      }
    } catch {
      // Fall through to text checks
    }
    return null;
  }

  const tierScoreLine = rawFileContent.match(/Certification Tier:\s*([A-Za-z0-9_-]+)\s*\((\d+(?:\.\d+)?)\/100\)/i);
  if (tierScoreLine) {
    const wrapperTier = tierScoreLine[1].trim().toUpperCase();
    const wrapperScore = Number(tierScoreLine[2]);
    if (typeof payload.tier === 'string' && wrapperTier !== payload.tier.trim().toUpperCase()) {
      return `Certificate header tier '${wrapperTier}' does not match signed JWS payload tier '${payload.tier}'`;
    }
    if (typeof payload.score === 'number' && wrapperScore !== payload.score) {
      return `Certificate header score (${wrapperScore}) does not match signed JWS payload score (${payload.score})`;
    }
  } else {
    const tierOnly = rawFileContent.match(/Certification Tier:\s*([A-Za-z0-9_-]+)/i);
    if (tierOnly && typeof payload.tier === 'string') {
      if (tierOnly[1].trim().toUpperCase() !== payload.tier.trim().toUpperCase()) {
        return `Certificate header tier '${tierOnly[1]}' does not match signed JWS payload tier '${payload.tier}'`;
      }
    }
  }

  const evalScoreLine = rawFileContent.match(/(?:Evaluated\s+)?Score:\s*(\d+(?:\.\d+)?)\s*(?:\/100|\b)/i);
  if (evalScoreLine && typeof payload.score === 'number') {
    if (Number(evalScoreLine[1]) !== payload.score) {
      return `Certificate header score (${evalScoreLine[1]}) does not match signed JWS payload score (${payload.score})`;
    }
  }

  return null;
}

export async function verifyCommand(tokenArg?: string, options: VerifyCommandOptions = {}): Promise<void> {
  let token = tokenArg || options.jws;
  let rawCertificateFileContent: string | undefined;

  if (options.file && fs.existsSync(options.file)) {
    rawCertificateFileContent = fs.readFileSync(options.file, 'utf8');
    if (!token) {
      const match = rawCertificateFileContent.match(
        /(?:tv_(?:live|ent)_)?eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/
      );
      if (match) token = match[0];
    }
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
      const signingInput = Buffer.from(`${headerB64}.${payloadB64}`);
      const sigBytes = Buffer.from(signature, 'base64url');
      const verifyWithKey = (key: crypto.KeyObject): boolean => {
        try {
          if (crypto.verify('sha256', signingInput, { key, dsaEncoding: 'ieee-p1363' }, sigBytes)) {
            return true;
          }
        } catch {
          // Try DER fallback
        }
        try {
          return crypto.verify('sha256', signingInput, key, sigBytes);
        } catch {
          return false;
        }
      };

      const candidateKeys: crypto.KeyObject[] = [];
      const localKey = resolveEs256PublicKey(options.publicKey, header.kid);
      if (localKey) candidateKeys.push(localKey);

      // If no explicit --public-key was forced, also allow Cloud JWKS discovery when local key is absent or for a different kid
      if (!options.publicKey) {
        const jwksKey = await fetchEs256PublicKeyFromJwks(header.kid, options.apiUrl);
        if (jwksKey) candidateKeys.push(jwksKey);
      }

      if (candidateKeys.length === 0) {
        console.error(
          '\n❌ Error: ES256 token requires a matching --public-key, HTTPS/loopback --api-url <cloud-url>, TOOLVETO_PUBLIC_KEY, or ~/.toolveto/keys/es256_keypair.json.'
        );
        process.exitCode = 1;
        return;
      }
      isValidSignature = candidateKeys.some((k) => verifyWithKey(k));
    } else if (header.alg === 'HS256') {
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
    } else {
      console.error(`\n❌ Error: Unsupported JWS algorithm '${header.alg}'. Only 'ES256' and 'HS256' are supported.`);
      process.exitCode = 1;
      return;
    }

    const nowSec = Math.floor(Date.now() / 1000);
    const expSec =
      typeof payload.exp === 'number' && Number.isFinite(payload.exp)
        ? payload.exp > 1e11
          ? Math.floor(payload.exp / 1000)
          : payload.exp
        : undefined;
    const iatSec =
      typeof payload.iat === 'number' && Number.isFinite(payload.iat)
        ? payload.iat > 1e11
          ? Math.floor(payload.iat / 1000)
          : payload.iat
        : nowSec;
    const missingExp = expSec === undefined && !options.allowNoExp;
    const isExpired = expSec !== undefined && nowSec > expSec;
    const wrapperMismatchReason =
      rawCertificateFileContent !== undefined
        ? verifyCertificateWrapperClaims(rawCertificateFileContent, payload)
        : null;

    console.log(`\n================================================================================`);
    console.log(`         TOOLVETO RFC 7515 ATTESTATION VERIFICATION`);
    console.log(`================================================================================`);

    if (isValidSignature && !isExpired && !missingExp && !wrapperMismatchReason) {
      console.log(`\n✅ STATUS: CRYPTOGRAPHICALLY VALID & COMPLIANT`);
    } else if (!isValidSignature) {
      console.log(`\n❌ STATUS: SIGNATURE MISMATCH (UNAUTHORIZED / TAMPERED)`);
    } else if (wrapperMismatchReason) {
      console.log(`\n❌ STATUS: CERTIFICATE WRAPPER TAMPERED (${wrapperMismatchReason})`);
    } else if (missingExp) {
      console.log(`\n❌ STATUS: MISSING EXPIRATION CLAIM (pass --allow-no-exp to override)`);
    } else {
      console.log(`\n⚠️ STATUS: TOKEN EXPIRED`);
    }

    console.log(`\nTarget / Subject:       ${payload.sub || payload.repo || 'unknown'}`);
    console.log(`Issuer:                 ${payload.iss || 'toolveto-evidence-engine'}`);
    console.log(`Algorithm:              ${header.alg || 'HS256'} (Key ID: ${header.kid || 'default'})`);
    console.log(`Evaluated Score:        ${payload.score ?? 'N/A'}/100 [ Tier: ${payload.tier || 'N/A'} ]`);
    console.log(`Fatal Veto Multiplier:  Φ = ${payload.phi != null ? payload.phi : 1.0}`);
    console.log(`Issued At:              ${new Date(iatSec * 1000).toISOString()}`);
    console.log(`Expires At:             ${expSec ? new Date(expSec * 1000).toISOString() : 'Missing'}`);

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

    if (!isValidSignature || isExpired || missingExp || wrapperMismatchReason) {
      process.exitCode = 1;
    }
  } catch (err: any) {
    console.error(`\n❌ Verification Failed: ${err.message}\n`);
    process.exitCode = 1;
  }
}
