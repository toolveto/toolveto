import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  StdioMcpClient,
  HttpMcpClient,
  McpToolDefinition,
  McpClient,
  McpPromptDefinition,
  McpResourceTemplateDefinition,
  StaticSourceFile,
} from '@toolveto/core';
import { extractSourceContextFromDir } from './static-extractors.js';

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
  sourceFiles?: StaticSourceFile[];
  resourceTemplates?: McpResourceTemplateDefinition[];
  prompts?: McpPromptDefinition[];
  transportMode?: 'stdio' | 'http' | 'sse' | 'dual' | 'unknown';
}

export function resolvePythonInterpreter(baseDir?: string): string {
  const candidates: string[] = [];
  if (baseDir) {
    candidates.push(path.join(baseDir, '.venv', 'bin', 'python'));
    candidates.push(path.join(baseDir, '.venv', 'Scripts', 'python.exe'));
  }
  const activeVenv = (process.env.VIRTUAL_ENV || '').trim();
  if (activeVenv) {
    candidates.push(path.join(activeVenv, 'bin', 'python'));
    candidates.push(path.join(activeVenv, 'Scripts', 'python.exe'));
  }
  const activeConda = (process.env.CONDA_PREFIX || '').trim();
  if (activeConda) {
    candidates.push(path.join(activeConda, 'bin', 'python'));
    candidates.push(path.join(activeConda, 'Scripts', 'python.exe'));
  }

  for (const c of candidates) {
    try {
      if (fs.existsSync(c) && fs.statSync(c).isFile()) {
        return c;
      }
    } catch {
      // Ignore unreadable path
    }
  }

  const pathDirs = (process.env.PATH || '').split(path.delimiter).filter(Boolean);
  const binNames =
    process.platform === 'win32'
      ? ['python.exe', 'python3.exe', 'python', 'python3']
      : ['python3', 'python'];

  for (const bin of binNames) {
    for (const dir of pathDirs) {
      const full = path.join(dir, bin);
      try {
        if (fs.existsSync(full) && fs.statSync(full).isFile()) {
          return bin.replace(/\.exe$/i, '') === bin ? bin : full;
        }
      } catch {
        // Continue searching PATH
      }
    }
  }

  return process.platform === 'win32' ? 'python' : 'python3';
}

function isExecutableBinaryFile(filePath: string): boolean {
  try {
    const st = fs.statSync(filePath);
    if (!st.isFile()) return false;
    const ext = path.extname(filePath).toLowerCase();
    if (ext !== '' && ext !== '.exe') return false;
    if (process.platform === 'win32') {
      return ext === '.exe' || (st.mode & 0o111) !== 0;
    }
    return (st.mode & 0o111) !== 0;
  } catch {
    return false;
  }
}

function extractBalancedBlock(
  source: string,
  openIndex: number,
  openChar: '(' | '{',
  closeChar: ')' | '}'
): string | null {
  let depth = 0;
  let inDouble = false;
  let inBacktick = false;
  let inLineComment = false;
  let inBlockComment = false;

  for (let i = openIndex; i < source.length; i++) {
    const ch = source[i];
    const next = i + 1 < source.length ? source[i + 1] : '';
    const prev = i > 0 ? source[i - 1] : '';

    if (inLineComment) {
      if (ch === '\n') inLineComment = false;
      continue;
    }
    if (inBlockComment) {
      if (ch === '*' && next === '/') {
        inBlockComment = false;
        i++;
      }
      continue;
    }
    if (!inDouble && !inBacktick) {
      if (ch === '/' && next === '/') {
        inLineComment = true;
        i++;
        continue;
      }
      if (ch === '/' && next === '*') {
        inBlockComment = true;
        i++;
        continue;
      }
    }

    if (!inBacktick && ch === '"' && prev !== '\\') {
      inDouble = !inDouble;
      continue;
    }
    if (!inDouble && ch === '`') {
      inBacktick = !inBacktick;
      continue;
    }
    if (inDouble || inBacktick) continue;

    if (ch === openChar) depth++;
    else if (ch === closeChar) {
      depth--;
      if (depth === 0) {
        return source.slice(openIndex + 1, i);
      }
    }
  }
  return null;
}

function unescapeGoString(raw: string): string {
  if (raw.startsWith('`') && raw.endsWith('`')) {
    return raw.slice(1, -1);
  }
  if (raw.startsWith('"') && raw.endsWith('"')) {
    try {
      return JSON.parse(raw);
    } catch {
      return raw.slice(1, -1);
    }
  }
  return raw;
}

function inferToolMutationFlag(name: string, readOnlyHint?: boolean, destructiveHint?: boolean): boolean {
  if (readOnlyHint === true) return false;
  if (destructiveHint === true) return true;
  return /^(create|update|delete|drop|remove|transfer|charge|pay|send|insert|upsert|mutate|write|post|put|patch|execute|run|settle|refund)/i.test(
    name
  );
}

function parseGoSourceForTools(source: string): McpToolDefinition[] {
  const discovered = new Map<string, McpToolDefinition>();

  // 1. mcp.NewTool("tool_name", mcp.WithDescription("..."), mcp.WithString("param", mcp.Required(), ...))
  const newToolRegex = /\b(?:mcp\.)?NewTool\s*\(/g;
  let match: RegExpExecArray | null;
  while ((match = newToolRegex.exec(source)) !== null) {
    const openIdx = match.index + match[0].length - 1;
    const body = extractBalancedBlock(source, openIdx, '(', ')');
    if (!body) continue;

    const nameMatch = body.match(/^\s*("(?:[^"\\]|\\.)*"|`[^`]*`)/);
    if (!nameMatch) continue;
    const name = unescapeGoString(nameMatch[1]).trim();
    if (!name) continue;

    let description = '';
    const descMatch = body.match(/\bWithDescription\s*\(\s*("(?:[^"\\]|\\.)*"|`[^`]*`)/);
    if (descMatch) {
      description = unescapeGoString(descMatch[1]);
    }

    const properties: Record<string, any> = {};
    const required: string[] = [];

    const propCallRegex = /\bWith(String|Number|Boolean|Array|Object)\s*\(/g;
    let pm: RegExpExecArray | null;
    while ((pm = propCallRegex.exec(body)) !== null) {
      const kind = pm[1].toLowerCase();
      const propOpenIdx = pm.index + pm[0].length - 1;
      const propBody = extractBalancedBlock(body, propOpenIdx, '(', ')');
      if (!propBody) continue;
      const pNameMatch = propBody.match(/^\s*("(?:[^"\\]|\\.)*"|`[^`]*`)/);
      if (!pNameMatch) continue;
      const pName = unescapeGoString(pNameMatch[1]).trim();
      if (!pName) continue;

      const propSchema: Record<string, any> = { type: kind };
      const pDescMatch = propBody.match(/\bDescription\s*\(\s*("(?:[^"\\]|\\.)*"|`[^`]*`)/);
      if (pDescMatch) {
        propSchema.description = unescapeGoString(pDescMatch[1]);
      }
      properties[pName] = propSchema;
      if (/\bRequired\s*\(\s*\)/.test(propBody)) {
        required.push(pName);
      }
    }

    const readOnlyHint = /ReadOnlyHint\s*:\s*(?:boolPtr\(\s*)?true\b/.test(body) ? true : undefined;
    const destructiveHint = /DestructiveHint\s*:\s*(?:boolPtr\(\s*)?true\b/.test(body) ? true : undefined;
    const idempotentHint = /IdempotentHint\s*:\s*(?:boolPtr\(\s*)?true\b/.test(body) ? true : undefined;

    discovered.set(name, {
      name,
      description,
      isMutation: inferToolMutationFlag(name, readOnlyHint, destructiveHint),
      ...(readOnlyHint !== undefined ? { readOnlyHint } : {}),
      ...(destructiveHint !== undefined ? { destructiveHint } : {}),
      ...(idempotentHint !== undefined ? { idempotentHint } : {}),
      inputSchema: {
        type: 'object',
        properties,
        ...(required.length > 0 ? { required } : {}),
      },
    });
  }

  // 2. RegisterTool("tool_name", ...) / AddTool(server, &mcp.Tool{...}) or RegisterTool("name", "desc", ...)
  const registerRegex = /\bRegisterTool\s*\(/g;
  while ((match = registerRegex.exec(source)) !== null) {
    const openIdx = match.index + match[0].length - 1;
    const body = extractBalancedBlock(source, openIdx, '(', ')');
    if (!body) continue;

    const strLiterals = Array.from(body.matchAll(/("(?:[^"\\]|\\.)*"|`[^`]*`)/g)).map((m) =>
      unescapeGoString(m[1])
    );
    const name = strLiterals[0]?.trim();
    if (!name || discovered.has(name)) continue;
    const description = strLiterals.length > 1 ? strLiterals[1] : '';

    discovered.set(name, {
      name,
      description,
      isMutation: inferToolMutationFlag(name),
      inputSchema: { type: 'object', properties: {} },
    });
  }

  // 3. Go struct literals: mcp.Tool{Name: "...", Description: "..."} or Tool{Name: "...", Description: "..."}
  const toolStructRegex = /\b(?:mcp\.)?Tool\s*\{/g;
  while ((match = toolStructRegex.exec(source)) !== null) {
    const openIdx = match.index + match[0].length - 1;
    const body = extractBalancedBlock(source, openIdx, '{', '}');
    if (!body) continue;

    const nameField = body.match(/\bName\s*:\s*("(?:[^"\\]|\\.)*"|`[^`]*`)/);
    if (!nameField) continue;
    const name = unescapeGoString(nameField[1]).trim();
    if (!name || discovered.has(name)) continue;

    const descField = body.match(/\bDescription\s*:\s*("(?:[^"\\]|\\.)*"|`[^`]*`)/);
    const description = descField ? unescapeGoString(descField[1]) : '';
    const readOnlyHint = /ReadOnlyHint\s*:\s*(?:boolPtr\(\s*)?true\b/.test(body) ? true : undefined;
    const destructiveHint = /DestructiveHint\s*:\s*(?:boolPtr\(\s*)?true\b/.test(body) ? true : undefined;

    discovered.set(name, {
      name,
      description,
      isMutation: inferToolMutationFlag(name, readOnlyHint, destructiveHint),
      ...(readOnlyHint !== undefined ? { readOnlyHint } : {}),
      ...(destructiveHint !== undefined ? { destructiveHint } : {}),
      inputSchema: { type: 'object', properties: {} },
    });
  }

  return Array.from(discovered.values());
}

/**
 * Statically extracts MCP tool definitions from Go source files (`.go` excluding `*_test.go` and `vendor/`).
 */
export function extractToolsStaticallyFromDir(dirPath: string): McpToolDefinition[] {
  const byName = new Map<string, McpToolDefinition>();
  const skipDirs = new Set(['vendor', 'node_modules', '.git', 'dist', 'build', '.turbo', 'testdata']);

  const walk = (current: string) => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (skipDirs.has(entry.name)) continue;
        walk(path.join(current, entry.name));
      } else if (entry.isFile() && entry.name.endsWith('.go') && !entry.name.endsWith('_test.go')) {
        const fullPath = path.join(current, entry.name);
        try {
          const content = fs.readFileSync(fullPath, 'utf-8');
          for (const tool of parseGoSourceForTools(content)) {
            if (!byName.has(tool.name)) {
              byName.set(tool.name, tool);
            }
          }
        } catch {
          // Ignore unreadable Go source file
        }
      }
    }
  };

  if (fs.existsSync(dirPath)) {
    const stat = fs.statSync(dirPath);
    if (stat.isDirectory()) {
      walk(dirPath);
    } else if (stat.isFile() && dirPath.endsWith('.go') && !dirPath.endsWith('_test.go')) {
      try {
        const content = fs.readFileSync(dirPath, 'utf-8');
        for (const tool of parseGoSourceForTools(content)) {
          byName.set(tool.name, tool);
        }
      } catch {
        // Ignore unreadable Go file
      }
    }
  }

  for (const extraTool of extractSourceContextFromDir(dirPath).tools) {
    if (!byName.has(extraTool.name)) {
      byName.set(extraTool.name, extraTool);
    }
  }

  return Array.from(byName.values());
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
  const normalizedTarget = (targetPath || '.').replace(/^stdio:\/\//i, '');
  let tools: McpToolDefinition[] = [];
  let client: McpClient | null = null;

  try {
    // 1. Remote Streamable HTTP MCP Server
    if (normalizedTarget && (normalizedTarget.startsWith('http://') || normalizedTarget.startsWith('https://'))) {
      const httpClient = new HttpMcpClient({
        baseUrl: normalizedTarget,
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
      const resolvedTarget = path.resolve(process.cwd(), normalizedTarget || '.');

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
        // 2b. Direct Go/TypeScript/TSX source file (safe zero-exec static AST extraction)
        else if (
          stat.isFile() &&
          (resolvedTarget.endsWith('.go') || resolvedTarget.endsWith('.ts') || resolvedTarget.endsWith('.tsx'))
        ) {
          tools = extractToolsStaticallyFromDir(resolvedTarget);
        }
        // 3. Executable Server script (Node / Python) or Compiled Binary (with --allow-exec)
        else if (stat.isFile()) {
          const ext = path.extname(resolvedTarget).toLowerCase();
          const isScriptExt = new Set(['.js', '.mjs', '.cjs', '.py']).has(ext);
          const isCompiledBin =
            (ext === '' || ext === '.exe') &&
            options.allowExec === true &&
            process.env.TOOLVETO_DISALLOW_AUTO_EXEC !== '1' &&
            isExecutableBinaryFile(resolvedTarget);

          if (!isScriptExt && !isCompiledBin) {
            throw new Error(`Refusing to auto-exec '${ext || path.basename(resolvedTarget)}'`);
          }
          if (options.allowExec === false || process.env.TOOLVETO_DISALLOW_AUTO_EXEC === '1') {
            if (isScriptExt) {
              tools = extractToolsStaticallyFromDir(resolvedTarget);
            } else {
              throw new Error('auto-exec disabled');
            }
          } else {
            const baseDir = path.dirname(resolvedTarget);
            const command = isCompiledBin
              ? resolvedTarget
              : ext === '.py'
                ? resolvePythonInterpreter(baseDir)
                : process.execPath;
            const args = isCompiledBin ? [] : [resolvedTarget];

            const stdioClient = new StdioMcpClient({
              command,
              args,
              cwd: baseDir,
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
        // 4. Directory containing server files, manifests, Go sources, or client configs
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
              const command = entrypoint.endsWith('.py')
                ? resolvePythonInterpreter(resolvedTarget)
                : process.execPath;
              const stdioClient = new StdioMcpClient({
                command,
                args: [entrypoint],
                cwd: resolvedTarget,
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

            // Static Go MCP tool discovery (safe, zero execution)
            if (tools.length === 0) {
              tools = extractToolsStaticallyFromDir(resolvedTarget);
            }

            // Optional compiled binary discovery when --allow-exec is explicitly authorized
            if (tools.length === 0 && options.allowExec === true && !execDisallowed) {
              const dirBase = path.basename(resolvedTarget);
              const binaryCandidates = [
                path.join(resolvedTarget, dirBase),
                path.join(resolvedTarget, `${dirBase}.exe`),
                path.join(resolvedTarget, 'server'),
                path.join(resolvedTarget, 'server.exe'),
                path.join(resolvedTarget, 'bin', dirBase),
                path.join(resolvedTarget, 'bin', 'server'),
              ];
              for (const bc of binaryCandidates) {
                if (!isExecutableBinaryFile(bc)) continue;
                const realBin = fs.realpathSync(bc);
                const relBin = path.relative(realTargetDir, realBin);
                if (relBin.startsWith('..') || path.isAbsolute(relBin)) continue;

                const stdioClient = new StdioMcpClient({
                  command: realBin,
                  args: [],
                  cwd: resolvedTarget,
                  timeoutMs,
                });
                await stdioClient.connect();
                tools = await stdioClient.listTools();
                if (options.keepClientOpen) {
                  client = stdioClient;
                } else {
                  await stdioClient.close();
                }
                if (tools.length > 0) break;
              }
            }
          }
        }
      }
    }

    const isRemoteHttp =
      Boolean(normalizedTarget) &&
      (normalizedTarget.startsWith('http://') || normalizedTarget.startsWith('https://'));
    const staticCtx = !isRemoteHttp
      ? extractSourceContextFromDir(path.resolve(process.cwd(), normalizedTarget || '.'))
      : { tools: [], sourceFiles: [], resourceTemplates: [], prompts: [], transportMode: 'http' as const };

    if (tools.length === 0 && staticCtx.tools.length > 0) {
      tools = staticCtx.tools;
    }

    if (tools.length === 0 && options.demo && options.demoFallbackTools) {
      tools = options.demoFallbackTools;
    }

    return {
      tools,
      client,
      sourceFiles: staticCtx.sourceFiles,
      resourceTemplates: staticCtx.resourceTemplates,
      prompts: staticCtx.prompts,
      transportMode: staticCtx.transportMode,
    };
  } catch (err) {
    if (client) {
      await client.close().catch(() => {});
    }
    throw err;
  }
}
