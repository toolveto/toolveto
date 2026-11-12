import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  StdioMcpClient,
  HttpMcpClient,
  McpToolDefinition,
  McpClient,
} from '@toolveto/core';

export interface DiscoverToolsOptions {
  timeoutMs?: number;
  allowExec?: boolean;
  demo?: boolean;
  keepClientOpen?: boolean;
  demoFallbackTools?: McpToolDefinition[];
}

export interface DiscoveredToolsResult {
  tools: McpToolDefinition[];
  client: McpClient | null;
}

export function extractToolsFromJson(parsed: any, baseDir: string): McpToolDefinition[] {
  if (Array.isArray(parsed)) {
    return parsed;
  }
  if (parsed && Array.isArray(parsed.tools)) {
    return parsed.tools;
  }
  if (parsed && parsed.name && parsed.inputSchema) {
    return [parsed];
  }
  if (parsed && parsed.mcpServers && typeof parsed.mcpServers === 'object') {
    const collected: McpToolDefinition[] = [];
    for (const [, serverCfg] of Object.entries<any>(parsed.mcpServers)) {
      if (!serverCfg || typeof serverCfg !== 'object') continue;
      if (Array.isArray(serverCfg.tools)) {
        collected.push(...serverCfg.tools);
      } else if (typeof serverCfg.toolsPath === 'string') {
        const tp = path.resolve(baseDir, serverCfg.toolsPath);
        const rel = path.relative(baseDir, tp);
        if (!rel.startsWith('..') && !path.isAbsolute(rel) && fs.existsSync(tp)) {
          try {
            const sub = JSON.parse(fs.readFileSync(tp, 'utf-8'));
            collected.push(...extractToolsFromJson(sub, path.dirname(tp)));
          } catch {
            // Ignore invalid sub-config
          }
        }
      }
    }
    return collected;
  }
  return [];
}

async function discoverLiveToolsFromMcpConfig(
  parsed: any,
  timeoutMs: number,
  allowExec?: boolean
): Promise<McpToolDefinition[]> {
  if (!parsed || typeof parsed.mcpServers !== 'object' || parsed.mcpServers === null) {
    return [];
  }
  const collected: McpToolDefinition[] = [];
  const execAllowed = allowExec === true && process.env.TOOLVETO_DISALLOW_AUTO_EXEC !== '1';

  for (const [, serverCfg] of Object.entries<any>(parsed.mcpServers)) {
    if (!serverCfg || typeof serverCfg !== 'object') continue;
    if (typeof serverCfg.url === 'string' && /^https?:\/\//i.test(serverCfg.url)) {
      const httpClient = new HttpMcpClient({ baseUrl: serverCfg.url, timeoutMs });
      try {
        await httpClient.connect();
        const serverTools = await httpClient.listTools();
        collected.push(...serverTools);
      } finally {
        await httpClient.close().catch(() => {});
      }
    } else if (execAllowed && typeof serverCfg.command === 'string' && serverCfg.command.trim()) {
      const args = Array.isArray(serverCfg.args) ? serverCfg.args.map(String) : [];
      const envObj: Record<string, string> = {};
      if (serverCfg.env && typeof serverCfg.env === 'object') {
        for (const [k, v] of Object.entries(serverCfg.env)) {
          if (typeof v === 'string' && !v.startsWith('${ENV:')) {
            envObj[k] = v;
          }
        }
      }
      const stdioClient = new StdioMcpClient({
        command: serverCfg.command,
        args,
        env: Object.keys(envObj).length > 0 ? envObj : undefined,
        timeoutMs,
      });
      try {
        await stdioClient.connect();
        const serverTools = await stdioClient.listTools();
        collected.push(...serverTools);
      } finally {
        await stdioClient.close().catch(() => {});
      }
    }
  }
  return collected;
}

export async function discoverToolsFromTarget(
  targetPath: string,
  options: DiscoverToolsOptions = {}
): Promise<DiscoveredToolsResult> {
  const timeoutMs = options.timeoutMs || 15000;
  let tools: McpToolDefinition[] = [];
  let client: McpClient | null = null;

  try {
    // 1. Remote Streamable HTTP MCP Server
    if (targetPath && (targetPath.startsWith('http://') || targetPath.startsWith('https://'))) {
      const httpClient = new HttpMcpClient({
        baseUrl: targetPath,
        timeoutMs,
      });
      await httpClient.connect();
      tools = await httpClient.listTools();
      if (options.keepClientOpen) {
        client = httpClient;
      } else {
        await httpClient.close();
      }
    } else {
      const resolvedTarget = path.resolve(process.cwd(), targetPath || '.');

      if (fs.existsSync(resolvedTarget)) {
        const stat = fs.statSync(resolvedTarget);

        // 2. Direct JSON Schema / Manifest / Multi-Server Config file
        if (stat.isFile() && resolvedTarget.endsWith('.json')) {
          const content = fs.readFileSync(resolvedTarget, 'utf-8');
          const parsed = JSON.parse(content);
          tools = extractToolsFromJson(parsed, path.dirname(resolvedTarget));
          if (tools.length === 0 && parsed?.mcpServers) {
            tools = await discoverLiveToolsFromMcpConfig(parsed, timeoutMs, options.allowExec);
          }
        }
        // 3. Executable Server script (Node / Python)
        else if (stat.isFile()) {
          const ext = path.extname(resolvedTarget).toLowerCase();
          if (!new Set(['.js', '.mjs', '.cjs', '.py', '.json']).has(ext)) {
            throw new Error(`Refusing to auto-exec '${ext}'`);
          }
          if (options.allowExec === false || process.env.TOOLVETO_DISALLOW_AUTO_EXEC === '1') {
            throw new Error('auto-exec disabled');
          }

          const command = resolvedTarget.endsWith('.py') ? 'python3' : process.execPath;
          const stdioClient = new StdioMcpClient({
            command,
            args: [resolvedTarget],
            timeoutMs,
          });
          await stdioClient.connect();
          tools = await stdioClient.listTools();
          if (options.keepClientOpen) {
            client = stdioClient;
          } else {
            await stdioClient.close();
          }
        }
        // 4. Directory containing server files, manifests, or client configs
        else if (stat.isDirectory()) {
          const jsonCandidates = [
            path.join(resolvedTarget, 'tools.json'),
            path.join(resolvedTarget, 'mcp.json'),
            path.join(resolvedTarget, 'schema.json'),
            path.join(resolvedTarget, '.cursor', 'mcp.json'),
            path.join(resolvedTarget, '.vscode', 'mcp.json'),
            path.join(resolvedTarget, 'claude_desktop_config.json'),
          ];

          for (const candidate of jsonCandidates) {
            if (fs.existsSync(candidate)) {
              const parsed = JSON.parse(fs.readFileSync(candidate, 'utf-8'));
              const extracted = extractToolsFromJson(parsed, path.dirname(candidate));
              if (extracted.length > 0) {
                tools = extracted;
                break;
              }
              if (parsed?.mcpServers) {
                const liveTools = await discoverLiveToolsFromMcpConfig(parsed, timeoutMs, options.allowExec);
                if (liveTools.length > 0) {
                  tools = liveTools;
                  break;
                }
              }
            }
          }

          if (tools.length === 0) {
            const realTargetDir = fs.realpathSync(resolvedTarget);
            const ALLOWED_EXEC_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.py']);
            const isSafeEntrypoint = (candidatePath: string): string | null => {
              if (!fs.existsSync(candidatePath) || !fs.statSync(candidatePath).isFile()) return null;
              const realCandidate = fs.realpathSync(candidatePath);
              const rel = path.relative(realTargetDir, realCandidate);
              if (rel.startsWith('..') || path.isAbsolute(rel)) {
                throw new Error(
                  `[ToolVeto CLI Security] Blocked path-traversal entrypoint '${candidatePath}' escaping target directory '${realTargetDir}'.`
                );
              }
              const ext = path.extname(realCandidate).toLowerCase();
              if (!ALLOWED_EXEC_EXTENSIONS.has(ext)) {
                return null;
              }
              return realCandidate;
            };

            let entrypoint: string | null = null;
            const pkgJsonPath = path.join(resolvedTarget, 'package.json');
            if (fs.existsSync(pkgJsonPath)) {
              let pkg: any;
              try {
                pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
              } catch {
                pkg = null;
              }
              if (pkg) {
                const mainCandidate =
                  typeof pkg.main === 'string'
                    ? pkg.main
                    : typeof pkg.bin === 'string'
                      ? pkg.bin
                      : pkg.bin && typeof pkg.bin === 'object'
                        ? (Object.values(pkg.bin)[0] as string)
                        : null;
                if (mainCandidate) {
                  const resolvedMain = path.resolve(resolvedTarget, mainCandidate);
                  const relMain = path.relative(resolvedTarget, resolvedMain);
                  if (relMain.startsWith('..') || path.isAbsolute(relMain)) {
                    throw new Error(
                      `[ToolVeto CLI Security] Blocked untrusted package.json entrypoint '${mainCandidate}' escaping target directory '${resolvedTarget}'.`
                    );
                  }
                  entrypoint = isSafeEntrypoint(resolvedMain);
                }
              }
            }

            if (!entrypoint) {
              const scriptCandidates = [
                path.join(resolvedTarget, 'index.js'),
                path.join(resolvedTarget, 'index.mjs'),
                path.join(resolvedTarget, 'dist', 'index.js'),
                path.join(resolvedTarget, 'build', 'index.js'),
                path.join(resolvedTarget, 'server.py'),
                path.join(resolvedTarget, 'main.py'),
              ];
              for (const sc of scriptCandidates) {
                const safeSc = isSafeEntrypoint(sc);
                if (safeSc) {
                  entrypoint = safeSc;
                  break;
                }
              }
            }

            const execDisallowed =
              options.allowExec === false || process.env.TOOLVETO_DISALLOW_AUTO_EXEC === '1';

            if (entrypoint && !execDisallowed) {
              const command = entrypoint.endsWith('.py') ? 'python3' : process.execPath;
              const stdioClient = new StdioMcpClient({
                command,
                args: [entrypoint],
                timeoutMs,
              });
              await stdioClient.connect();
              tools = await stdioClient.listTools();
              if (options.keepClientOpen) {
                client = stdioClient;
              } else {
                await stdioClient.close();
              }
            }
          }
        }
      }
    }

    if (tools.length === 0 && options.demo && options.demoFallbackTools) {
      tools = options.demoFallbackTools;
    }

    return { tools, client };
  } catch (err) {
    if (client) {
      await client.close().catch(() => {});
    }
    throw err;
  }
}
