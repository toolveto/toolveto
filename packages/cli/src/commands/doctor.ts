import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';

export interface DoctorCommandOptions {
  ide?: 'cursor' | 'claude' | 'windsurf' | 'vscode' | 'auto' | string;
  fix?: boolean;
  json?: boolean;
  registryUrl?: string;
}

export interface DoctorFinding {
  id: string;
  serverName: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: 'PLAINTEXT_SECRET' | 'FLOATING_PACKAGE' | 'UNWRAPPED_SHIELD' | 'TOOL_SHADOWING';
  message: string;
  remediation: string;
}

export interface DoctorReport {
  configPath: string;
  ideClient: string;
  totalServers: number;
  healthyServers: number;
  score: number;
  fixedCount: number;
  findings: DoctorFinding[];
  lockfilePath?: string;
  secretsBackupPath?: string;
}

const SECRET_KEY_NAMES = /(?:api[_-]?key|secret|token|password|passwd|private[_-]?key|auth|credential)/i;
const SECRET_VALUE_PATTERNS = [
  /^sk-[a-zA-Z0-9_-]{12,}/,
  /^ghp_[a-zA-Z0-9]{20,}/,
  /^github_pat_[a-zA-Z0-9_]{20,}/,
  /^xox[baprs]-[a-zA-Z0-9-]{10,}/,
  /^AKIA[0-9A-Z]{16}$/,
  /^eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/,
  /^postgres(?:ql)?:\/\/[^:$]+:[^@${]+@/i,
];

function resolveIdeConfigFile(targetPath?: string, ide: string = 'auto'): { path: string | null; ideClient: string } {
  const home = process.env.HOME || os.homedir();

  if (targetPath) {
    const resolved = path.resolve(process.cwd(), targetPath);
    if (fs.existsSync(resolved)) {
      const stat = fs.statSync(resolved);
      if (stat.isFile()) {
        return { path: resolved, ideClient: ide === 'auto' ? 'custom' : ide };
      }
      if (stat.isDirectory()) {
        const candidates: Array<{ file: string; client: string }> = [
          { file: path.join(resolved, '.cursor', 'mcp.json'), client: 'cursor' },
          { file: path.join(resolved, '.vscode', 'mcp.json'), client: 'vscode' },
          { file: path.join(resolved, 'claude_desktop_config.json'), client: 'claude' },
          { file: path.join(resolved, 'mcp.json'), client: 'mcp' },
        ];
        for (const c of candidates) {
          if (fs.existsSync(c.file) && fs.statSync(c.file).isFile()) {
            return { path: c.file, ideClient: c.client };
          }
        }
      }
    }
    return { path: null, ideClient: ide };
  }

  const searchOrder: Array<{ file: string; client: string }> = [];
  if (ide === 'cursor' || ide === 'auto') {
    searchOrder.push({ file: path.resolve(process.cwd(), '.cursor', 'mcp.json'), client: 'cursor' });
    searchOrder.push({ file: path.join(home, '.cursor', 'mcp.json'), client: 'cursor' });
  }
  if (ide === 'vscode' || ide === 'auto') {
    searchOrder.push({ file: path.resolve(process.cwd(), '.vscode', 'mcp.json'), client: 'vscode' });
  }
  if (ide === 'claude' || ide === 'auto') {
    searchOrder.push({ file: path.resolve(process.cwd(), 'claude_desktop_config.json'), client: 'claude' });
    searchOrder.push({
      file: path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
      client: 'claude',
    });
    searchOrder.push({ file: path.join(home, '.config', 'Claude', 'claude_desktop_config.json'), client: 'claude' });
  }
  if (ide === 'windsurf' || ide === 'auto') {
    searchOrder.push({ file: path.join(home, '.codeium', 'windsurf', 'mcp_config.json'), client: 'windsurf' });
  }

  for (const item of searchOrder) {
    if (fs.existsSync(item.file) && fs.statSync(item.file).isFile()) {
      return { path: item.file, ideClient: item.client };
    }
  }

  return { path: null, ideClient: ide };
}

function stripFloatingVersionSuffix(pkgSpec: string): string {
  // Preserve leading '@' for scoped packages like '@modelcontextprotocol/server-github@latest'
  const lastAt = pkgSpec.lastIndexOf('@');
  if (lastAt > 0) {
    return pkgSpec.slice(0, lastAt);
  }
  return pkgSpec;
}

async function resolveNpmLatestVersion(pkgName: string, registryBaseUrl: string): Promise<string | null> {
  try {
    const cleanRegistry = registryBaseUrl.replace(/\/+$/, '');
    const encodedPkg = pkgName.startsWith('@')
      ? `@${encodeURIComponent(pkgName.slice(1))}`
      : encodeURIComponent(pkgName);
    const res = await fetch(`${cleanRegistry}/${encodedPkg}/latest`, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(2500),
    });
    if (!res.ok) return null;
    const body = (await res.json()) as { version?: string };
    if (typeof body?.version === 'string' && /^\d+\.\d+\.\d+/.test(body.version)) {
      return body.version;
    }
    return null;
  } catch {
    return null;
  }
}

function isFloatingPackageArg(cmd: string, args: string[]): { floating: boolean; pkg?: string } {
  const normalizedCmd = path.basename(cmd).toLowerCase();
  if (!['npx', 'uvx', 'bunx', 'pnpx'].includes(normalizedCmd)) {
    return { floating: false };
  }

  for (const arg of args) {
    if (arg.startsWith('-')) continue;
    if (arg === 'toolveto' || arg === '@toolveto/cli' || arg === 'proxy') continue;
    if (arg.endsWith('@latest') || arg.endsWith('@next') || arg.endsWith('@main')) {
      return { floating: true, pkg: arg };
    }
    const atIndex = arg.lastIndexOf('@');
    if (atIndex <= 0) {
      return { floating: true, pkg: arg };
    }
    const versionPart = arg.slice(atIndex + 1);
    if (!/^\d+\.\d+/.test(versionPart)) {
      return { floating: true, pkg: arg };
    }
    return { floating: false, pkg: arg };
  }

  return { floating: false };
}

function saveExtractedSecretsSecurely(configDir: string, extracted: Map<string, string>): string {
  const envFilePath = path.join(configDir, '.env.toolveto.secrets');
  const existingMap = new Map<string, string>();

  if (fs.existsSync(envFilePath)) {
    const lines = fs.readFileSync(envFilePath, 'utf-8').split(/\r?\n/);
    for (const line of lines) {
      const m = line.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
      if (m) {
        existingMap.set(m[1], m[2]);
      }
    }
  }

  for (const [k, v] of extracted) {
    existingMap.set(k, JSON.stringify(v));
  }

  const serialized =
    [
      '# ToolVeto IDE Doctor — Extracted Secrets Vault (chmod 0600)',
      '# Source this file or load into your OS keychain before launching your IDE.',
      ...Array.from(existingMap.entries()).map(([k, v]) => `${k}=${v}`),
    ].join('\n') + '\n';

  fs.writeFileSync(envFilePath, serialized, { encoding: 'utf-8', mode: 0o600 });
  try {
    fs.chmodSync(envFilePath, 0o600);
  } catch {
    // ignore on platforms without POSIX chmod
  }
  return envFilePath;
}

export async function doctorCommand(
  targetPath?: string,
  options: DoctorCommandOptions = {}
): Promise<DoctorReport | undefined> {
  const idePref = (options.ide || 'auto').toLowerCase();
  const registryUrl =
    options.registryUrl || process.env.TOOLVETO_NPM_REGISTRY || 'https://registry.npmjs.org';
  const resolved = resolveIdeConfigFile(targetPath, idePref);

  if (!resolved.path) {
    console.error(
      `\n❌ Error: Could not locate MCP IDE config file (checked Cursor, VS Code, Claude Desktop, Windsurf).`
    );
    console.error(`Pass an explicit path via 'npx toolveto doctor <path-to-mcp.json>'.\n`);
    process.exitCode = 1;
    return undefined;
  }

  let parsed: Record<string, any>;
  try {
    parsed = JSON.parse(fs.readFileSync(resolved.path, 'utf-8'));
  } catch (err: any) {
    console.error(`\n❌ Error: Failed to parse IDE MCP config at ${resolved.path}: ${err.message}\n`);
    process.exitCode = 1;
    return undefined;
  }

  const servers: Record<string, any> =
    parsed && typeof parsed.mcpServers === 'object' && parsed.mcpServers !== null ? parsed.mcpServers : {};
  const serverEntries = Object.entries(servers);
  const findings: DoctorFinding[] = [];
  const unhealthyServerSet = new Set<string>();
  const extractedSecrets = new Map<string, string>();
  let fixedCount = 0;

  for (const [serverName, entry] of serverEntries) {
    if (!entry || typeof entry !== 'object') continue;

    const cmd = String(entry.command || '');
    const args: string[] = Array.isArray(entry.args) ? entry.args.map(String) : [];

    // 1. Check for floating unpinned npx / uvx package versions (Supply-Chain Rug-Pull vector)
    const floatCheck = isFloatingPackageArg(cmd, args);
    if (floatCheck.floating && floatCheck.pkg) {
      unhealthyServerSet.add(serverName);
      const basePkgName = stripFloatingVersionSuffix(floatCheck.pkg);
      const normalizedCmd = path.basename(cmd).toLowerCase();

      let resolvedVersion: string | null = null;
      if (options.fix && ['npx', 'bunx', 'pnpx'].includes(normalizedCmd)) {
        resolvedVersion = await resolveNpmLatestVersion(basePkgName, registryUrl);
      }

      const examplePinned = resolvedVersion ? `${basePkgName}@${resolvedVersion}` : `${basePkgName}@<exact-semver>`;
      findings.push({
        id: 'DOC-PIN-001',
        serverName,
        severity: 'HIGH',
        category: 'FLOATING_PACKAGE',
        message: `Server '${serverName}' executes unpinned floating package '${floatCheck.pkg}' via ${cmd} (Supply-Chain Rug-Pull risk).`,
        remediation: resolvedVersion
          ? `Pinned to verified registry release '${examplePinned}'.`
          : `Pin an immutable published semantic version (e.g. '${examplePinned}') after verifying against your package registry.`,
      });

      if (options.fix && resolvedVersion && Array.isArray(entry.args)) {
        const pinnedSpec = `${basePkgName}@${resolvedVersion}`;
        entry.args = entry.args.map((a: string) => (a === floatCheck.pkg ? pinnedSpec : a));
        fixedCount++;
      }
    }

    // 2. Check for plaintext API keys / secrets in env block
    if (entry.env && typeof entry.env === 'object') {
      for (const [envKey, envVal] of Object.entries(entry.env)) {
        const strVal = String(envVal || '').trim();
        if (!strVal || strVal.startsWith('${') || strVal.startsWith('$')) continue;

        const looksLikeSecretValue = SECRET_VALUE_PATTERNS.some((re) => re.test(strVal));
        const looksLikeSecretKey = SECRET_KEY_NAMES.test(envKey) && strVal.length >= 8;

        if (looksLikeSecretValue || looksLikeSecretKey) {
          unhealthyServerSet.add(serverName);
          findings.push({
            id: 'DOC-SEC-001',
            serverName,
            severity: 'CRITICAL',
            category: 'PLAINTEXT_SECRET',
            message: `Server '${serverName}' exposes plaintext credential in env.${envKey} inside IDE config file.`,
            remediation: `Replace literal secret with environment reference '\${ENV:${envKey}}' (saved to .env.toolveto.secrets with 0600 permissions).`,
          });

          if (options.fix) {
            extractedSecrets.set(envKey, strVal);
            entry.env[envKey] = `\${ENV:${envKey}}`;
            fixedCount++;
          }
        }
      }
    }

    // 3. Check if server is wrapped with @toolveto/shield runtime protection
    const isWrapped =
      Boolean(entry._toolvetoOriginal) ||
      args.some((a) => a.includes('toolveto') || a.includes('@toolveto/shield'));
    if (!isWrapped) {
      findings.push({
        id: 'DOC-SHIELD-001',
        serverName,
        severity: 'MEDIUM',
        category: 'UNWRAPPED_SHIELD',
        message: `Server '${serverName}' is not wrapped with @toolveto/shield runtime circuit-breaker & token budget proxy.`,
        remediation: `Run 'npx toolveto wrap ${resolved.path}' to enable runtime loop & context-bomb protection.`,
      });
    }
  }

  let lockfilePath: string | undefined;
  let secretsBackupPath: string | undefined;
  if (options.fix) {
    if (extractedSecrets.size > 0) {
      secretsBackupPath = saveExtractedSecretsSecurely(path.dirname(resolved.path), extractedSecrets);
    }
    fs.writeFileSync(resolved.path, JSON.stringify(parsed, null, 2) + '\n', 'utf-8');
    lockfilePath = path.join(path.dirname(resolved.path), 'toolveto-ide.lock.json');
    const pinEntries: Record<string, { sha256: string; command: string }> = {};
    for (const [serverName, entry] of serverEntries) {
      if (!entry || typeof entry !== 'object') continue;
      const canonical = JSON.stringify({
        command: entry.command || '',
        args: entry.args || [],
        url: entry.url || '',
      });
      pinEntries[serverName] = {
        sha256: 'sha256:' + crypto.createHash('sha256').update(canonical).digest('hex'),
        command: [entry.command, ...(entry.args || [])].filter(Boolean).join(' ') || entry.url || serverName,
      };
    }
    fs.writeFileSync(
      lockfilePath,
      JSON.stringify(
        {
          version: '1.0',
          generatedAt: new Date().toISOString(),
          ideClient: resolved.ideClient,
          configPath: resolved.path,
          servers: pinEntries,
        },
        null,
        2
      ) + '\n',
      'utf-8'
    );
  }

  const totalServers = serverEntries.length;
  const healthyServers = Math.max(0, totalServers - unhealthyServerSet.size);
  const criticalCount = findings.filter((f) => f.severity === 'CRITICAL').length;
  const highCount = findings.filter((f) => f.severity === 'HIGH').length;
  const mediumCount = findings.filter((f) => f.severity === 'MEDIUM').length;
  const score = Math.max(0, 100 - criticalCount * 35 - highCount * 20 - mediumCount * 5);

  const report: DoctorReport = {
    configPath: resolved.path,
    ideClient: resolved.ideClient,
    totalServers,
    healthyServers,
    score,
    fixedCount,
    findings,
    lockfilePath,
    secretsBackupPath,
  };

  if (!options.fix && (criticalCount > 0 || highCount > 0)) {
    process.exitCode = 1;
  }

  if (options.json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(`\n🩺 ToolVeto IDE Doctor — Local MCP Configuration Audit`);
    console.log(`   Config File: ${report.configPath} (${report.ideClient.toUpperCase()})`);
    console.log(`   Servers:     ${report.healthyServers}/${report.totalServers} passing supply-chain & secret hygiene`);
    console.log(`   Health Score: ${report.score}/100\n`);

    if (findings.length === 0) {
      console.log(`✅ Zero IDE configuration vulnerabilities detected.\n`);
    } else {
      for (const f of findings) {
        const icon = f.severity === 'CRITICAL' ? '🛑' : f.severity === 'HIGH' ? '⚠️' : 'ℹ️';
        console.log(`${icon} [${f.severity}] ${f.id} (${f.serverName}): ${f.message}`);
        console.log(`   ↳ Fix: ${f.remediation}`);
      }
      console.log('');
    }

    if (options.fix && lockfilePath) {
      console.log(`🔒 Remediated plaintext secrets & generated IDE pinfile: ${lockfilePath}`);
      if (secretsBackupPath) {
        console.log(`🔐 Preserved extracted secrets in vault (chmod 0600): ${secretsBackupPath}`);
      }
      console.log('');
    }
  }

  return report;
}
