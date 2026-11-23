import * as fs from 'node:fs';

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
      const headers: Record<string, string> = {
        Authorization: `Bearer ${this.licenseKey}`,
        Accept: 'application/json',
      };
      if (this.etag) headers['If-None-Match'] = this.etag;
      const res = await fetch(`${this.apiUrl}/api/v1/catalog/policy`, {
        method: 'GET',
        headers,
        signal: AbortSignal.timeout(5_000),
      });
      if (res.status === 304) {
        this.lastSyncedAt = Date.now();
        return this.policy;
      }
      if (res.ok) {
        const data = (await res.json()) as { policy?: OrgCatalogPolicyDocument; etag?: string };
        if (data?.policy) {
          this.policy = data.policy;
          this.etag = res.headers.get('etag') || data.etag || this.etag;
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
