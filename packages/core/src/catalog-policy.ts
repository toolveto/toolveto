import * as dns from 'node:dns';
import * as fs from 'node:fs';
import * as https from 'node:https';
import * as net from 'node:net';

function expandCatalogIpv6Hextets(ip: string): number[] | null {
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

function isBlockedCatalogIpOrHost(rawHost: string): boolean {
  const host = rawHost.toLowerCase().trim().replace(/^\[|\]$/g, '').split('%')[0].replace(/\.+$/, '');
  if (
    !host ||
    host === '0.0.0.0' ||
    host === 'localhost' ||
    host === '127.0.0.1' ||
    host === '::1' ||
    host === '::' ||
    host === '169.254.169.254' ||
    host === 'metadata.google.internal' ||
    host.endsWith('.localhost') ||
    host.endsWith('.internal') ||
    host.endsWith('.local')
  ) {
    return true;
  }
  const v = net.isIP(host);
  if (v === 4) {
    const [a, b] = host.split('.').map(Number);
    return (
      a === 0 || a === 10 || a === 127 ||
      (a === 169 && b === 254) || (a === 192 && b === 168) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 100 && b >= 64 && b <= 127) ||
      (a === 198 && (b === 18 || b === 19)) || a >= 224
    );
  }
  if (v === 6) {
    const h = expandCatalogIpv6Hextets(host);
    if (!h) return true;
    if ((h[0] & 0xe000) !== 0x2000) return true;
    if (h[0] === 0x2002) return true;
    if (h[0] === 0x2001 && (h[1] === 0x0000 || h[1] === 0x0002 || h[1] === 0x0db8)) return true;
    if (h[0] === 0x3ffe || (h[0] === 0x3fff && (h[1] & 0xf000) === 0x0000)) return true;
    return false;
  }
  return false;
}

export type OrgCatalogStatus = 'APPROVED' | 'UNDER_REVIEW' | 'QUARANTINED' | 'BLOCKED';

export interface OrgCatalogPolicyEntry {
  serverPattern: string;
  status: OrgCatalogStatus;
  pinnedSha256?: string;
  minRequiredScore?: number;
  reason?: string;
}

export interface OrgCatalogPolicyDocument {
  schemaVersion: 'toolveto-org-catalog/v1';
  tenantId?: string;
  generatedAt: number;
  graceWindowHours: number;
  entries: OrgCatalogPolicyEntry[];
}

export interface OrgCatalogAccessDecision {
  allowed: boolean;
  code?: number;
  status?: OrgCatalogStatus;
  reason?: string;
  matchedPattern?: string;
}

function matchesGlob(pattern: string, candidate: string): boolean {
  const parts = pattern.split('*').filter((seg) => seg.length > 0);
  if (parts.length === 0) return true;
  let cursor = 0;
  for (let i = 0; i < parts.length; i += 1) {
    const idx = candidate.indexOf(parts[i], cursor);
    if (idx === -1) return false;
    cursor = idx + parts[i].length;
  }
  return true;
}

function matchesPattern(pattern: string, candidates: string[]): boolean {
  const p = pattern.trim().toLowerCase();
  if (!p) return false;
  if (p === '*') return true;
  if (p.includes('*')) {
    return candidates.some((c) => matchesGlob(p, c));
  }
  return candidates.some((c) => c === p || c.includes(p));
}

export function evaluateOrgCatalogAccess(
  policy: OrgCatalogPolicyDocument | null | undefined,
  serverIdentifier: string,
  extraIdentifiers: string[] = []
): OrgCatalogAccessDecision {
  if (!policy || !Array.isArray(policy.entries) || policy.entries.length === 0) {
    return { allowed: true };
  }

  const candidates = [serverIdentifier, ...extraIdentifiers]
    .map((s) => String(s || '').trim().toLowerCase())
    .filter(Boolean);

  // Strict fail-closed priority: QUARANTINED / BLOCKED always override APPROVED
  for (const status of ['QUARANTINED', 'BLOCKED'] as const) {
    const blocked = policy.entries.find(
      (e) => e.status === status && matchesPattern(e.serverPattern, candidates)
    );
    if (blocked) {
      return {
        allowed: false,
        code: -32004,
        status,
        matchedPattern: blocked.serverPattern,
        reason: `ORG_CATALOG_${status}: Server '${serverIdentifier}' is ${status.toLowerCase()} by organization policy${
          blocked.reason ? ` (${blocked.reason})` : ''
        }`,
      };
    }
  }

  const approved = policy.entries.find(
    (e) => e.status === 'APPROVED' && matchesPattern(e.serverPattern, candidates)
  );
  if (approved) {
    return { allowed: true, status: 'APPROVED', matchedPattern: approved.serverPattern };
  }

  return { allowed: true };
}

export class OrgCatalogPolicyClient {
  private policy: OrgCatalogPolicyDocument | null = null;
  private etag: string | null = null;
  private lastSyncedAt = 0;
  private readonly pollIntervalMs: number;
  private readonly apiUrl?: string;
  private readonly licenseKey?: string;
  private pollTimer: ReturnType<typeof setInterval> | null = null;

  constructor(options: {
    apiUrl?: string;
    licenseKey?: string;
    initialPolicy?: OrgCatalogPolicyDocument;
    policyFile?: string;
    pollIntervalMs?: number;
  } = {}) {
    this.apiUrl = options.apiUrl?.replace(/\/+$/, '');
    this.licenseKey = options.licenseKey;
    this.pollIntervalMs = Math.max(5_000, options.pollIntervalMs ?? 60_000);

    if (options.initialPolicy) {
      this.policy = options.initialPolicy;
      this.lastSyncedAt = Date.now();
    } else if (options.policyFile && fs.existsSync(options.policyFile)) {
      const parsed = JSON.parse(fs.readFileSync(options.policyFile, 'utf8'));
      this.policy = parsed.policy || parsed;
      this.lastSyncedAt = Date.now();
    }
  }

  public getPolicy(): OrgCatalogPolicyDocument | null {
    if (!this.policy) return null;
    const graceMs = Math.max(1, this.policy.graceWindowHours || 72) * 3_600_000;
    if (this.lastSyncedAt > 0 && Date.now() - this.lastSyncedAt > graceMs) {
      return this.policy; // Still enforce known quarantines even past grace window!
    }
    return this.policy;
  }

  public async syncNow(): Promise<OrgCatalogPolicyDocument | null> {
    if (!this.apiUrl || !this.licenseKey) return this.policy;
    try {
      const parsedApi = new URL(`${this.apiUrl}/api/v1/catalog/policy`);
      if (parsedApi.username || parsedApi.password || parsedApi.protocol !== 'https:') return this.policy;
      const cleanHost = parsedApi.hostname.toLowerCase().replace(/^\[|\]$/g, '').split('%')[0].replace(/\.+$/, '');
      if (isBlockedCatalogIpOrHost(cleanHost)) return this.policy;
      let pinnedAddr: { address: string; family: number } | null = null;
      if (net.isIP(cleanHost) === 0) {
        const addrs = await dns.promises.lookup(cleanHost, { all: true });
        if (!addrs.length || addrs.some((a) => isBlockedCatalogIpOrHost(a.address))) return this.policy;
        pinnedAddr = { address: addrs[0].address, family: addrs[0].family };
      }
      const headers: Record<string, string> = {
        Authorization: `Bearer ${this.licenseKey}`,
        Accept: 'application/json',
      };
      if (this.etag) headers['If-None-Match'] = this.etag;
      const resData = await new Promise<{ status: number; etag?: string; body: string }>((resolve, reject) => {
        const req = https.request(
          parsedApi,
          {
            method: 'GET',
            headers,
            timeout: 5_000,
            ...(pinnedAddr
              ? {
                  lookup: (_host: string, optsOrCb: any, maybeCb?: any) => {
                    const cb = typeof optsOrCb === 'function' ? optsOrCb : maybeCb;
                    const opts = typeof optsOrCb === 'object' && optsOrCb !== null ? optsOrCb : {};
                    if (typeof cb !== 'function') return;
                    if (opts.all) {
                      process.nextTick(() => cb(null, [{ address: pinnedAddr!.address, family: pinnedAddr!.family }]));
                    } else {
                      process.nextTick(() => cb(null, pinnedAddr!.address, pinnedAddr!.family));
                    }
                  },
                  servername: cleanHost,
                }
              : {}),
          },
          (res) => {
            const status = res.statusCode || 0;
            if (status >= 300 && status < 400) {
              res.resume();
              reject(new Error(`HTTP redirect (${status}) blocked`));
              return;
            }
            const chunks: Buffer[] = [];
            res.on('data', (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
            res.on('end', () =>
              resolve({
                status,
                etag: typeof res.headers.etag === 'string' ? res.headers.etag : undefined,
                body: Buffer.concat(chunks).toString('utf8'),
              })
            );
          }
        );
        req.on('error', reject);
        req.on('timeout', () => req.destroy(new Error('timeout')));
        req.end();
      });
      if (resData.status === 304) {
        this.lastSyncedAt = Date.now();
        return this.policy;
      }
      if (resData.status >= 200 && resData.status < 300) {
        const data = JSON.parse(resData.body) as { policy?: OrgCatalogPolicyDocument; etag?: string };
        if (data?.policy) {
          this.policy = data.policy;
          this.etag = resData.etag || data.etag || this.etag;
          this.lastSyncedAt = Date.now();
        }
      }
    } catch {
      // Offline grace window (72h): retain last verified catalog policy
    }
    return this.policy;
  }

  public startPolling(): void {
    if (!this.apiUrl || !this.licenseKey || this.pollTimer) return;
    void this.syncNow();
    this.pollTimer = setInterval(() => {
      void this.syncNow();
    }, this.pollIntervalMs);
    if (typeof this.pollTimer.unref === 'function') {
      this.pollTimer.unref();
    }
  }

  public stop(): void {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  }

  public evaluate(serverIdentifier: string, extraIdentifiers: string[] = []): OrgCatalogAccessDecision {
    return evaluateOrgCatalogAccess(this.getPolicy(), serverIdentifier, extraIdentifiers);
  }
}
