import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

export interface WrapCommandOptions {
  client?: 'cursor' | 'claude' | 'windsurf' | 'auto' | string;
  tokenBudget?: string | number;
  strict?: boolean;
  unwrap?: boolean;
  dryRun?: boolean;
}

export interface WrapResult {
  configPath: string;
  wrappedServers: string[];
  unwrappedServers: string[];
  collisions: string[];
  config: Record<string, any>;
}

function resolveConfigFile(targetPath?: string, client: string = 'auto'): string | null {
  const home = process.env.HOME || os.homedir();

  if (targetPath) {
    const resolved = path.resolve(process.cwd(), targetPath);
    if (fs.existsSync(resolved)) {
      const stat = fs.statSync(resolved);
      if (stat.isFile()) {
        return resolved;
      }
      if (stat.isDirectory()) {
        const dirCandidates = [
          path.join(resolved, '.cursor', 'mcp.json'),
          path.join(resolved, 'claude_desktop_config.json'),
          path.join(resolved, 'mcp.json'),
        ];
        for (const c of dirCandidates) {
          if (fs.existsSync(c) && fs.statSync(c).isFile()) {
            return c;
          }
        }
      }
    }
    return null;
  }

  const candidates: string[] = [];
  if (client === 'cursor' || client === 'auto') {
    candidates.push(path.resolve(process.cwd(), '.cursor', 'mcp.json'));
    candidates.push(path.join(home, '.cursor', 'mcp.json'));
  }
  if (client === 'claude' || client === 'auto') {
    candidates.push(path.resolve(process.cwd(), 'claude_desktop_config.json'));
    candidates.push(path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'));
    candidates.push(path.join(home, '.config', 'Claude', 'claude_desktop_config.json'));
  }
  if (client === 'windsurf' || client === 'auto') {
    candidates.push(path.join(home, '.codeium', 'windsurf', 'mcp_config.json'));
  }

  for (const candidate of candidates) {
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
      return candidate;
    }
  }

  return null;
}

export async function wrapCommand(
  targetPath?: string,
  options: WrapCommandOptions = {}
): Promise<WrapResult | undefined> {
  const clientType = options.client || 'auto';
  const tokenBudget = options.tokenBudget !== undefined ? Number(options.tokenBudget) || 4000 : 4000;
  const configPath = resolveConfigFile(targetPath, clientType);

  if (!configPath) {
    console.error(`\n❌ Error: Could not locate MCP client configuration file (checked Cursor, Claude Desktop, Windsurf).`);
    console.error(`Pass an explicit path via 'npx toolveto wrap <path-to-mcp.json>'.\n`);
    process.exitCode = 1;
    return undefined;
  }

  let parsed: Record<string, any>;
  try {
    const raw = fs.readFileSync(configPath, 'utf-8');
    parsed = JSON.parse(raw);
  } catch (err: any) {
    console.error(`\n❌ Error: Failed to parse MCP config at ${configPath}: ${err.message}\n`);
    process.exitCode = 1;
    return undefined;
  }

  if (!parsed || typeof parsed.mcpServers !== 'object' || parsed.mcpServers === null) {
    console.error(`\n❌ Error: Config file at ${configPath} does not contain a valid 'mcpServers' object.\n`);
    process.exitCode = 1;
    return undefined;
  }

  const servers = parsed.mcpServers as Record<string, any>;
  const wrappedServers: string[] = [];
  const unwrappedServers: string[] = [];
  const collisions: string[] = [];

  if (options.unwrap) {
    for (const [serverName, entry] of Object.entries(servers)) {
      if (entry && typeof entry === 'object' && entry._toolvetoOriginal) {
        entry.command = entry._toolvetoOriginal.command;
        entry.args = Array.isArray(entry._toolvetoOriginal.args) ? entry._toolvetoOriginal.args : [];
        delete entry._toolvetoOriginal;
        unwrappedServers.push(serverName);
      }
    }

    if (options.dryRun) {
      console.log(JSON.stringify(parsed, null, 2));
    } else {
      fs.writeFileSync(configPath, JSON.stringify(parsed, null, 2) + '\n', 'utf-8');
      console.log(`\n🔓 ToolVeto Unwrap Complete: Restored ${unwrappedServers.length} MCP server(s) in ${configPath}`);
      for (const name of unwrappedServers) {
        console.log(`   - ${name}`);
      }
      console.log('');
    }

    return {
      configPath,
      wrappedServers,
      unwrappedServers,
      collisions,
      config: parsed,
    };
  }

  // Detect cross-server inline tool name collisions or duplicate upstream commands
  const toolOwnerMap = new Map<string, string>();
  const commandOwnerMap = new Map<string, string>();

  for (const [serverName, entry] of Object.entries(servers)) {
    if (!entry || typeof entry !== 'object') continue;

    if (Array.isArray(entry.tools)) {
      for (const t of entry.tools) {
        const tName = typeof t === 'string' ? t : t?.name;
        if (tName) {
          const prevOwner = toolOwnerMap.get(tName);
          if (prevOwner && prevOwner !== serverName) {
            collisions.push(`Tool '${tName}' is declared by both '${prevOwner}' and '${serverName}' (Tool Shadowing risk)`);
          } else {
            toolOwnerMap.set(tName, serverName);
          }
        }
      }
    }

    const rawCmd = entry._toolvetoOriginal
      ? [entry._toolvetoOriginal.command, ...(entry._toolvetoOriginal.args || [])].join(' ').trim()
      : [entry.command, ...(entry.args || [])].join(' ').trim();
    if (rawCmd) {
      const prevCmdOwner = commandOwnerMap.get(rawCmd);
      if (prevCmdOwner && prevCmdOwner !== serverName) {
        collisions.push(`Duplicate upstream command '${rawCmd}' shared by '${prevCmdOwner}' and '${serverName}'`);
      } else {
        commandOwnerMap.set(rawCmd, serverName);
      }
    }
  }

  for (const [serverName, entry] of Object.entries(servers)) {
    if (!entry || typeof entry !== 'object') continue;
    if (entry._toolvetoOriginal) {
      // Already wrapped
      continue;
    }

    const origCommand = entry.command || '';
    const origArgs: string[] = Array.isArray(entry.args) ? entry.args : [];
    const originalCommandString = [origCommand, ...origArgs].filter(Boolean).join(' ').trim() || entry.url || serverName;

    entry._toolvetoOriginal = {
      command: origCommand,
      args: origArgs,
    };

    entry.command = 'npx';
    entry.args = [
      '-y',
      'toolveto',
      'proxy',
      '--upstream',
      originalCommandString,
      '--token-budget',
      String(tokenBudget),
      ...(options.strict ? ['--strict'] : []),
    ];

    wrappedServers.push(serverName);
  }

  if (options.dryRun) {
    console.log(JSON.stringify(parsed, null, 2));
  } else {
    fs.writeFileSync(configPath, JSON.stringify(parsed, null, 2) + '\n', 'utf-8');
    console.log(`\n🛡️  ToolVeto Shield Wrapper Active (${configPath})`);
    console.log(`Wrapped ${wrappedServers.length} MCP server(s): ${wrappedServers.join(', ') || 'none (already wrapped)'}`);
    console.log(`Active @toolveto/shield Protections:`);
    console.log(`   ✓ RFC 8785 Canonical SHA-256 Idempotency Deduplication`);
    console.log(`   ✓ 5-call / 30s Runaway Retry Loop Circuit Breaker`);
    console.log(`   ✓ ${tokenBudget}-Token Context Bomb Truncator & Cursor Pagination`);
    console.log(`   ✓ Cryptographic Rug-Pull & Schema Drift Lock Guard`);
    if (options.strict) {
      console.log(`   ✓ Fail-Closed Strict Mode Enforced (--strict)`);
    }
    if (collisions.length > 0) {
      console.warn(`\n⚠️  Cross-Server Warnings Detected:`);
      for (const c of collisions) {
        console.warn(`   - ${c}`);
      }
    }
    console.log('');
  }

  return {
    configPath,
    wrappedServers,
    unwrappedServers,
    collisions,
    config: parsed,
  };
}
