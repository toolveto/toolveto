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
  category:
    | 'PLAINTEXT_SECRET'
    | 'FLOATING_PACKAGE'
    | 'UNWRAPPED_SHIELD'
    | 'TOOL_SHADOWING'
    | 'SUPPLY_CHAIN';
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
  const normalizedCmd = path.basename(cmd).toLowerCase().replace(/\.cmd$/i, '');
  if (!['npx', 'uvx', 'bunx', 'pnpx'].includes(normalizedCmd)) {
    return { floating: false };
  }

  // If already wrapped by `npx -y toolveto proxy --stdio ... -- <origCmd> <origArgs...>`, inspect downstream args if npx
  const dashDashIdx = args.indexOf('--');
  if (args.includes('toolveto') && args.includes('proxy') && dashDashIdx >= 0) {
    const downstreamCmd = args[dashDashIdx + 1] || '';
    const downstreamArgs = args.slice(dashDashIdx + 2);
    return isFloatingPackageArg(downstreamCmd, downstreamArgs);
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

function saveSecretsToToolVetoVault(extractedByServer: Map<string, Map<string, string>>): string {
  const home = process.env.HOME || os.homedir();
  const vaultDir = path.join(home, '.toolveto');
  if (!fs.existsSync(vaultDir)) {
    fs.mkdirSync(vaultDir, { recursive: true, mode: 0o700 });
  }
  try {
    fs.chmodSync(vaultDir, 0o700);
  } catch (chmodErr) {
    process.stderr.write(`[toolveto] warning: unable to restrict vault permissions (${chmodErr instanceof Error ? chmodErr.message : String(chmodErr)})\n`);
  }

  const envFilePath = path.join(vaultDir, 'secrets.env');
  const existingUnscoped = new Map<string, string>();
  const existingScoped = new Map<string, Map<string, string>>();

  if (fs.existsSync(envFilePath)) {
    let currentSection: string | null = null;
    const lines = fs.readFileSync(envFilePath, 'utf-8').split(/\r?\n/);
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const secMatch = trimmed.match(/^\[([^\]]+)\]$/);
      if (secMatch) {
        currentSection = secMatch[1].trim();
        if (!existingScoped.has(currentSection)) {
          existingScoped.set(currentSection, new Map());
        }
        continue;
      }
      const m = trimmed.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
      if (m) {
        if (currentSection) {
          existingScoped.get(currentSection)!.set(m[1], m[2]);
        } else {
          existingUnscoped.set(m[1], m[2]);
        }
      }
    }
  }

  for (const [serverName, secMap] of extractedByServer) {
    if (!existingScoped.has(serverName)) {
      existingScoped.set(serverName, new Map());
    }
    const targetMap = existingScoped.get(serverName)!;
    for (const [k, v] of secMap) {
      targetMap.set(k, JSON.stringify(v));
    }
  }

  const outLines: string[] = [
    '# ToolVeto IDE Doctor — Secrets Vault (chmod 0600)',
    '# Automatically loaded at runtime by `toolveto proxy --stdio --server <name>`.',
  ];
  for (const [k, v] of existingUnscoped.entries()) {
    outLines.push(`${k}=${v}`);
  }
  for (const [serverName, secMap] of existingScoped.entries()) {
    if (secMap.size === 0) continue;
    outLines.push(`[${serverName}]`);
    for (const [k, v] of secMap.entries()) {
      outLines.push(`${k}=${v}`);
    }
  }

  const serialized = outLines.join('\n') + '\n';

  fs.writeFileSync(envFilePath, serialized, { encoding: 'utf-8', mode: 0o600 });
  try {
    fs.chmodSync(envFilePath, 0o600);
  } catch {
    // ignore on platforms without POSIX chmod
  }
  return envFilePath;
}

function wrapEntryWithShieldProxy(entry: Record<string, any>, npxBin: string, serverName?: string): boolean {
  if (entry._toolvetoOriginal) return true;
  const hasHttpUrl = typeof entry.url === 'string' && /^https?:\/\//i.test(entry.url);
  const hasStdioCommand = typeof entry.command === 'string' && entry.command.trim().length > 0;
  if (!hasHttpUrl && !hasStdioCommand) return false;

  const origCommand = typeof entry.command === 'string' ? entry.command : '';
  const origArgs: string[] = Array.isArray(entry.args) ? entry.args.map(String) : [];
  const origUrl = typeof entry.url === 'string' ? entry.url : undefined;

  entry._toolvetoOriginal = {
    hasCommand: 'command' in entry,
    command: origCommand,
    hasArgs: 'args' in entry,
    args: origArgs,
    hasUrl: 'url' in entry,
    ...(origUrl !== undefined ? { url: origUrl } : {}),
  };

  const baseProxyArgs = [
    '-y',
    'toolveto',
    'proxy',
    '--stdio',
    '--token-budget',
    '4000',
    ...(serverName ? ['--server', serverName] : []),
  ];
  if (hasHttpUrl && !hasStdioCommand) {
    delete entry.url;
    entry.command = npxBin;
    entry.args = [...baseProxyArgs, '--upstream', origUrl!];
  } else {
    entry.command = npxBin;
    entry.args = [...baseProxyArgs, '--', origCommand, ...origArgs];
  }
  return true;
}

export async function doctorCommand(
  targetPath?: string,
  options: DoctorCommandOptions = {}
): Promise<DoctorReport | undefined> {
  const idePref = (options.ide || 'auto').toLowerCase();
  const registryUrl =
    options.registryUrl || process.env.TOOLVETO_NPM_REGISTRY || 'https://registry.npmjs.org';
  const resolved = resolveIdeConfigFile(targetPath, idePref);
  const npxBin = process.platform === 'win32' ? 'npx.cmd' : 'npx';

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
  const extractedSecrets = new Map<string, Map<string, string>>();
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
      const normalizedCmd = path.basename(cmd).toLowerCase().replace(/\.cmd$/i, '');

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

    // 2. Check if server is wrapped with @toolveto/shield runtime protection
    let isWrapped =
      Boolean(entry._toolvetoOriginal) ||
      args.some((a) => a.includes('toolveto') || a.includes('@toolveto/shield'));
    if (!isWrapped) {
      findings.push({
        id: 'DOC-SHIELD-001',
        serverName,
        severity: 'MEDIUM',
        category: 'UNWRAPPED_SHIELD',
        message: `Server '${serverName}' is not wrapped with @toolveto/shield runtime circuit-breaker & token budget proxy.`,
        remediation: `Wrap via 'npx toolveto wrap ${resolved.path}' (or 'toolveto doctor --fix') to enable runtime loop & context-bomb protection.`,
      });

      if (options.fix) {
        if (wrapEntryWithShieldProxy(entry, npxBin, serverName)) {
          isWrapped = true;
          fixedCount++;
        }
      }
    }

    // 3. Check for plaintext API keys / secrets in env block
    // NEVER rewrite env values to literal "${ENV:KEY}" strings, which break Cursor & Claude Desktop!
    // When wrapped by `toolveto proxy --stdio`, migrate plaintext secrets safely to chmod-0600 ~/.toolveto/secrets.env.
    if (entry.env && typeof entry.env === 'object') {
      const migratedKeys: string[] = [];
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
            remediation: `Migrate secret to ~/.toolveto/secrets.env (chmod 0600) loaded at runtime by 'toolveto proxy --stdio'.`,
          });

          if (options.fix && isWrapped) {
            if (!extractedSecrets.has(serverName)) {
              extractedSecrets.set(serverName, new Map());
            }
            extractedSecrets.get(serverName)!.set(envKey, strVal);
            migratedKeys.push(envKey);
            fixedCount++;
          }
        }
      }

      if (options.fix && migratedKeys.length > 0) {
        for (const k of migratedKeys) {
          delete entry.env[k];
        }
        if (Object.keys(entry.env).length === 0) {
          delete entry.env;
        }
      }
    }
  }

  // DOC-SUPPLY-002: IDE supply-chain typosquatting, mutable git/http refs, unsafe flags, and lockfile tamper detection
  const KNOWN_MCP_PACKAGES = [
    '@modelcontextprotocol/server-github',
    '@modelcontextprotocol/server-filesystem',
    '@modelcontextprotocol/server-postgres',
    '@modelcontextprotocol/server-memory',
    '@modelcontextprotocol/server-fetch',
    '@modelcontextprotocol/server-puppeteer',
    '@modelcontextprotocol/server-slack',
    '@modelcontextprotocol/server-sequential-thinking',
    'mcp-server-git',
    'mcp-server-fetch',
    'mcp-server-sqlite',
    'mcp-server-time',
  ];
  const levenshtein = (a: string, b: string): number => {
    const dp: number[][] = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0));
    for (let i = 0; i <= a.length; i++) dp[i]![0] = i;
    for (let j = 0; j <= b.length; j++) dp[0]![j] = j;
    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        dp[i]![j] = Math.min(
          dp[i - 1]![j]! + 1,
          dp[i]![j - 1]! + 1,
          dp[i - 1]![j - 1]! + (a[i - 1] === b[j - 1] ? 0 : 1)
        );
      }
    }
    return dp[a.length]![b.length]!;
  };

  const siblingLockPath = path.join(path.dirname(resolved.path), 'toolveto-ide.lock.json');
  let existingLockServers: Record<string, { sha256?: string }> | null = null;
  if (!options.fix && fs.existsSync(siblingLockPath)) {
    try {
      const lockParsed = JSON.parse(fs.readFileSync(siblingLockPath, 'utf-8'));
      if (lockParsed && typeof lockParsed.servers === 'object') {
        existingLockServers = lockParsed.servers;
      }
    } catch {
      existingLockServers = null;
    }
  }

  for (const [serverName, entry] of serverEntries) {
    if (!entry || typeof entry !== 'object') continue;
    const cmd = String(entry.command || '').trim();
    const args: string[] = Array.isArray(entry.args) ? entry.args.map(String) : [];
    const url = String(entry.url || '').trim();

    if (url && /^http:\/\//i.test(url) && !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])([:/]|$)/i.test(url)) {
      unhealthyServerSet.add(serverName);
      findings.push({
        id: 'DOC-SUPPLY-002',
        serverName,
        severity: 'HIGH',
        category: 'SUPPLY_CHAIN',
        message: `Server '${serverName}' connects to non-loopback plaintext HTTP endpoint '${url}'.`,
        remediation: `Use HTTPS/TLS for remote MCP server URLs to prevent credential interception.`,
      });
    }

    const joined = `${cmd} ${args.join(' ')}`;
    if (/--allow-all|--dangerously-skip-permissions|--yolo\b|--no-sandbox|\b(curl|wget)\b[^|]*\|\s*(sh|bash|zsh)\b/i.test(joined)) {
      unhealthyServerSet.add(serverName);
      findings.push({
        id: 'DOC-SUPPLY-002',
        serverName,
        severity: 'CRITICAL',
        category: 'SUPPLY_CHAIN',
        message: `Server '${serverName}' uses dangerous shell pipe or sandbox/permission bypass flags in IDE command.`,
        remediation: `Remove unsafe bypass flags / piped shell installers and use a pinned, sandboxed MCP executable.`,
      });
    }

    for (const arg of args) {
      if (/^(git\+https?:|github:|gitlab:|bitbucket:)/i.test(arg) && !/#[0-9a-f]{40}$/i.test(arg)) {
        unhealthyServerSet.add(serverName);
        findings.push({
          id: 'DOC-SUPPLY-002',
          serverName,
          severity: 'HIGH',
          category: 'SUPPLY_CHAIN',
          message: `Server '${serverName}' loads mutable git dependency '${arg}' without an immutable 40-char commit SHA pin.`,
          remediation: `Pin git dependencies to a full 40-character commit SHA or publish/pin an immutable npm/PyPI release.`,
        });
      }

      if (!arg.startsWith('-') && !arg.includes('/') && !arg.startsWith('.') && arg.length >= 6 || arg.startsWith('@')) {
        const pkgBase = arg.startsWith('@')
          ? arg.replace(/^(@[^/]+\/[^@]+)@.+$/, '$1').toLowerCase()
          : arg.replace(/@.+$/, '').toLowerCase();
        if (!KNOWN_MCP_PACKAGES.includes(pkgBase)) {
          const spoofMatch = KNOWN_MCP_PACKAGES.find((known) => {
            const dist = levenshtein(pkgBase, known);
            return dist >= 1 && dist <= 2;
          });
          if (spoofMatch) {
            unhealthyServerSet.add(serverName);
            findings.push({
              id: 'DOC-SUPPLY-002',
              serverName,
              severity: 'HIGH',
              category: 'SUPPLY_CHAIN',
              message: `Potential MCP package typosquat on '${serverName}': '${pkgBase}' is within edit distance 2 of official '${spoofMatch}'.`,
              remediation: `Verify package spelling against '${spoofMatch}' before executing inside IDE.`,
            });
          }
        }
      }
    }

    if (existingLockServers) {
      const canonical = JSON.stringify({
        command: entry.command || '',
        args: entry.args || [],
        url: entry.url || '',
      });
      const currentSha = 'sha256:' + crypto.createHash('sha256').update(canonical).digest('hex');
      const expectedSha = existingLockServers[serverName]?.sha256;
      if (!expectedSha || expectedSha !== currentSha) {
        unhealthyServerSet.add(serverName);
        findings.push({
          id: 'DOC-SUPPLY-002',
          serverName,
          severity: 'CRITICAL',
          category: 'SUPPLY_CHAIN',
          message: !expectedSha
            ? `Server '${serverName}' was added to IDE config without an entry in toolveto-ide.lock.json (unpinned supply-chain drift).`
            : `Server '${serverName}' SHA-256 drifted from toolveto-ide.lock.json (${expectedSha.slice(0, 18)}... != ${currentSha.slice(0, 18)}...).`,
          remediation: `Inspect recent config edits and run 'npx toolveto doctor --fix' after verifying package integrity.`,
        });
      }
    }
  }

  let lockfilePath: string | undefined;
  let secretsBackupPath: string | undefined;
  if (options.fix) {
    if (extractedSecrets.size > 0) {
      secretsBackupPath = saveSecretsToToolVetoVault(extractedSecrets);
    }
    if (fs.existsSync(resolved.path)) {
      const bakPath = `${resolved.path}.bak`;
      fs.copyFileSync(resolved.path, bakPath);
      try {
        fs.chmodSync(bakPath, 0o600);
      } catch {
        // Best-effort permission restriction on non-POSIX filesystems
      }
    }
    fs.writeFileSync(resolved.path, JSON.stringify(parsed, null, 2) + '\n', { encoding: 'utf-8', mode: 0o600 });
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
      console.log(`🔒 Pinned versions, wrapped servers with Shield & generated IDE pinfile: ${lockfilePath}`);
      if (secretsBackupPath) {
        console.log(`🔐 Migrated plaintext secrets to runtime vault (chmod 0600): ${secretsBackupPath}`);
      }
      console.log('');
    }
  }

  return report;
}
