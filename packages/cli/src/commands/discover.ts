import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  OrgCatalogPolicyClient,
  type OrgCatalogPolicyDocument,
} from '@toolveto/core';

export interface DiscoverOptions {
  target?: string;
  json?: boolean;
  upload?: boolean;
  enforceCatalog?: boolean;
  policyFile?: string;
  apiUrl?: string;
  token?: string;
  hostSalt?: string;
  configPaths?: Array<{ ideClient: string; filePath: string }>;
}

export interface DiscoveredShadowServer {
  serverName: string;
  ideClient: string;
  configPath: string;
  commandSignature: string;
  isWrapped: boolean;
  hasPlaintextSecret: boolean;
  hasFloatingLatest: boolean;
  manifestSha256: string;
  catalogStatus?: string;
  catalogReason?: string;
}

export interface DiscoverReport {
  schemaVersion: 'toolveto-discover/v1';
  hostHmac: string;
  scannedAt: number;
  configsInspected: number;
  servers: DiscoveredShadowServer[];
  summary: {
    totalServers: number;
    unwrappedCount: number;
    plaintextSecretCount: number;
    floatingLatestCount: number;
    quarantinedCount: number;
    lethalTrifectaExposed: boolean;
  };
  uploaded?: boolean;
  uploadError?: string;
}

const SECRET_KEY_PATTERN = /(key|token|secret|password|passwd|auth|bearer|credential|dsn|private)/i;
const SECRET_VALUE_PATTERN =
  /(\b(?:sk_live|sk_test|ghp|gho|xoxb|xoxp|AKIA|tv_live|tv_enroll)_[A-Za-z0-9_-]{8,}\b|Bearer\s+[A-Za-z0-9._-]{16,})/gi;

export function computeHostHmac(salt?: string): string {
  const configuredSalt = salt || process.env.TOOLVETO_HOST_SALT;
  if (!configuredSalt) {
    console.warn('[ToolVeto Discover] TOOLVETO_HOST_SALT is unset; falling back to default pseudonymization salt.');
  }
  const effectiveSalt = configuredSalt || 'toolveto-mdm-pseudonym-v1';
  const rawIdentity = `${os.hostname()}:${os.userInfo().username}:${os.platform()}`;
  const digest = crypto.createHmac('sha256', effectiveSalt).update(rawIdentity, 'utf8').digest('hex').slice(0, 24);
  return `HOST_${digest}`;
}

export function sanitizeCommandSignatureZeroSecret(command: string, args: string[]): string {
  const safeArgs = args.map((arg) => {
    const s = String(arg || '');
    if (SECRET_VALUE_PATTERN.test(s)) {
      SECRET_VALUE_PATTERN.lastIndex = 0;
      return '[REDACTED]';
    }
    if (/^--?(?:api[-_]?key|token|secret|password|auth)=.+/i.test(s)) {
      return `${s.split('=')[0]}=[REDACTED]`;
    }
    return s;
  });
  return [command, ...safeArgs]
    .join(' ')
    .replace(SECRET_VALUE_PATTERN, '[REDACTED]')
    .trim()
    .slice(0, 320);
}

function detectPlaintextSecrets(envObj: unknown, args: string[]): boolean {
  if (envObj && typeof envObj === 'object' && !Array.isArray(envObj)) {
    for (const [k, v] of Object.entries(envObj as Record<string, unknown>)) {
      const val = String(v ?? '').trim();
      if (!val) continue;
      // References like ${ENV_VAR} or $ENV_VAR are safe; literal secret values are flagged
      if (/^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/.test(val)) continue;
      if (SECRET_KEY_PATTERN.test(k) && val.length >= 8) return true;
      if (SECRET_VALUE_PATTERN.test(val)) {
        SECRET_VALUE_PATTERN.lastIndex = 0;
        return true;
      }
    }
  }
  for (const arg of args) {
    if (SECRET_VALUE_PATTERN.test(String(arg || ''))) {
      SECRET_VALUE_PATTERN.lastIndex = 0;
      return true;
    }
  }
  return false;
}

export function getDefaultIdeConfigCandidates(projectDir = process.cwd()): Array<{ ideClient: string; filePath: string }> {
  const home = os.homedir();
  const candidates: Array<{ ideClient: string; filePath: string }> = [
    { ideClient: 'cursor-project', filePath: path.join(projectDir, '.cursor', 'mcp.json') },
    { ideClient: 'vscode-project', filePath: path.join(projectDir, '.vscode', 'mcp.json') },
    { ideClient: 'cursor-global', filePath: path.join(home, '.cursor', 'mcp.json') },
    { ideClient: 'windsurf', filePath: path.join(home, '.codeium', 'windsurf', 'mcp_config.json') },
    { ideClient: 'claude-code', filePath: path.join(home, '.claude.json') },
    {
      ideClient: 'claude-desktop',
      filePath:
        process.platform === 'darwin'
          ? path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')
          : process.platform === 'win32'
            ? path.join(process.env.APPDATA || path.join(home, 'AppData', 'Roaming'), 'Claude', 'claude_desktop_config.json')
            : path.join(home, '.config', 'Claude', 'claude_desktop_config.json'),
    },
  ];
  return candidates;
}

function extractMcpServersMap(parsed: any): Record<string, any> {
  if (!parsed || typeof parsed !== 'object') return {};
  if (parsed.mcpServers && typeof parsed.mcpServers === 'object') return parsed.mcpServers;
  if (parsed.servers && typeof parsed.servers === 'object') return parsed.servers;
  return {};
}

export function scanLocalMcpConfigs(options: DiscoverOptions = {}): DiscoverReport {
  const targetDir = options.target ? path.resolve(process.cwd(), options.target) : process.cwd();
  const candidates =
    options.configPaths && options.configPaths.length > 0
      ? options.configPaths
      : getDefaultIdeConfigCandidates(targetDir);

  const servers: DiscoveredShadowServer[] = [];
  let configsInspected = 0;

  for (const cand of candidates) {
    if (!fs.existsSync(cand.filePath)) continue;
    configsInspected += 1;
    let parsed: any;
    try {
      parsed = JSON.parse(fs.readFileSync(cand.filePath, 'utf8'));
    } catch {
      continue;
    }

    const mcpMap = extractMcpServersMap(parsed);
    for (const [serverName, def] of Object.entries(mcpMap)) {
      if (!def || typeof def !== 'object') continue;
      const command = String(def.command || def.url || '');
      const args = Array.isArray(def.args) ? def.args.map(String) : [];
      const fullRaw = [command, ...args].join(' ');
      const isWrapped =
        Boolean(def._toolvetoOriginal) ||
        /\btoolveto\b.*\b(proxy|wrap)\b/i.test(fullRaw) ||
        /@toolveto\/shield/i.test(fullRaw);
      const hasPlaintextSecret = detectPlaintextSecrets(def.env, args);
      const hasFloatingLatest = /@latest\b|\bnpx\s+(?:-y\s+)?[^@\s]+(?:\s|$)/i.test(fullRaw) && !/@\d+\.\d+\.\d+/.test(fullRaw);
      const commandSignature = sanitizeCommandSignatureZeroSecret(command, args);
      const manifestSha256 = crypto
        .createHash('sha256')
        .update(`${serverName}:${commandSignature}`)
        .digest('hex');

      servers.push({
        serverName,
        ideClient: cand.ideClient,
        configPath: cand.filePath,
        commandSignature,
        isWrapped,
        hasPlaintextSecret,
        hasFloatingLatest,
        manifestSha256,
      });
    }
  }

  const hasIngest = servers.some((s) => /(github|fetch|web|browser|search|brave|firecrawl)/i.test(`${s.serverName} ${s.commandSignature}`));
  const hasPriv = servers.some((s) => /(postgres|supabase|neon|sqlite|mysql|mongo|filesystem|gdrive|hubspot|crm|memory)/i.test(`${s.serverName} ${s.commandSignature}`));
  const hasEgress = servers.some((s) => /(slack|email|gmail|twilio|stripe|webhook|github)/i.test(`${s.serverName} ${s.commandSignature}`));

  return {
    schemaVersion: 'toolveto-discover/v1',
    hostHmac: computeHostHmac(options.hostSalt),
    scannedAt: Date.now(),
    configsInspected,
    servers,
    summary: {
      totalServers: servers.length,
      unwrappedCount: servers.filter((s) => !s.isWrapped).length,
      plaintextSecretCount: servers.filter((s) => s.hasPlaintextSecret).length,
      floatingLatestCount: servers.filter((s) => s.hasFloatingLatest).length,
      quarantinedCount: 0,
      lethalTrifectaExposed: hasIngest && hasPriv && hasEgress && servers.length >= 2,
    },
  };
}

export async function discoverCommand(options: DiscoverOptions = {}): Promise<DiscoverReport> {
  const report = scanLocalMcpConfigs(options);
  const apiUrl = (options.apiUrl || process.env.TOOLVETO_API_URL || 'https://toolveto.ai').replace(/\/+$/, '');
  const token =
    options.token ||
    process.env.TOOLVETO_ENROLL_TOKEN ||
    process.env.TOOLVETO_LICENSE_KEY ||
    process.env.TOOLVETO_TOKEN ||
    '';

  if (options.enforceCatalog || options.policyFile) {
    let loadedPolicy: OrgCatalogPolicyDocument | null = null;
    const policyClient = new OrgCatalogPolicyClient({
      apiUrl: token ? apiUrl : undefined,
      licenseKey: token || undefined,
      policyFile: options.policyFile,
    });
    loadedPolicy = await policyClient.syncNow();
    if (loadedPolicy) {
      let quarantinedCount = 0;
      for (const srv of report.servers) {
        const decision = policyClient.evaluate(srv.serverName, [srv.commandSignature]);
        srv.catalogStatus = decision.status || (decision.allowed ? 'UNREVIEWED' : 'QUARANTINED');
        if (!decision.allowed) {
          quarantinedCount += 1;
          srv.catalogReason = decision.reason;
        }
      }
      report.summary.quarantinedCount = quarantinedCount;
      if (quarantinedCount > 0) {
        process.exitCode = 1;
      }
    }
  }

  if (options.upload) {
    if (!token) {
      report.uploaded = false;
      report.uploadError = 'Missing enrollment or license token (--token or TOOLVETO_ENROLL_TOKEN)';
      process.exitCode = 1;
    } else {
      try {
        // Strictly zero-secret upload payload (never includes raw env values or local file paths!)
        const uploadBody = {
          hostHmac: report.hostHmac,
          servers: report.servers.map((s) => ({
            serverName: s.serverName,
            ideClient: s.ideClient,
            commandSignature: s.commandSignature,
            isWrapped: s.isWrapped,
            hasPlaintextSecret: s.hasPlaintextSecret,
            hasFloatingLatest: s.hasFloatingLatest,
            manifestSha256: s.manifestSha256,
          })),
        };
        const res = await fetch(`${apiUrl}/api/v1/fleet/inventory`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify(uploadBody),
          signal: AbortSignal.timeout(10_000),
        });
        if (!res.ok) {
          report.uploaded = false;
          report.uploadError = `Upload failed (${res.status})`;
          process.exitCode = 1;
        } else {
          report.uploaded = true;
        }
      } catch (err: any) {
        report.uploaded = false;
        report.uploadError = err?.message || 'Network error';
        process.exitCode = 1;
      }
    }
  }

  if (options.json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(`\n🛡️  ToolVeto Shadow MCP Discovery (${report.hostHmac})`);
    console.log(
      `   Configs scanned: ${report.configsInspected} • Servers found: ${report.summary.totalServers} • Unwrapped: ${report.summary.unwrappedCount} • Plaintext Secrets: ${report.summary.plaintextSecretCount} • Floating @latest: ${report.summary.floatingLatestCount}`
    );
    if (report.summary.lethalTrifectaExposed) {
      console.log(`   ⚠️  CRITICAL: Cross-MCP Lethal Trifecta exposure detected across discovered IDE servers!`);
    }
    if (report.summary.quarantinedCount > 0) {
      console.log(`   ❌ BLOCKED: ${report.summary.quarantinedCount} server(s) quarantined by Enterprise Approved Catalog!`);
    }
    for (const s of report.servers) {
      const flags = [
        s.isWrapped ? 'SHIELDED' : 'UNWRAPPED',
        s.hasPlaintextSecret ? 'PLAINTEXT_SECRET' : null,
        s.hasFloatingLatest ? 'FLOATING_LATEST' : null,
        s.catalogStatus && s.catalogStatus !== 'UNREVIEWED' ? `CATALOG:${s.catalogStatus}` : null,
      ]
        .filter(Boolean)
        .join(', ');
      console.log(`   • [${s.ideClient}] ${s.serverName} — ${flags}`);
    }
    console.log('');
  }

  return report;
}
