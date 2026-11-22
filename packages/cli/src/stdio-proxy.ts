import { spawn, ChildProcessWithoutNullStreams } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as readline from 'node:readline';
import { Readable, Writable } from 'node:stream';
import { ShieldMiddleware } from '@toolveto/shield';
import { OrgCatalogPolicyClient, type OrgCatalogPolicyDocument } from '@toolveto/core';
import {
  ALLOWED_CLIENT_NOTIFICATIONS,
  CloudTelemetrySyncer,
  loadLockfileHashesFromDisk,
  MAX_JSONRPC_BATCH_SIZE,
  parseGatewayUpstreamBody,
} from 'toolveto-gateway';

export interface StdioShieldProxyOptions {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  serverName?: string;
  upstreamUrl?: string;
  upstreamHeaders?: Record<string, string>;
  tokenBudget?: number;
  loopLimit?: number;
  strict?: boolean;
  lockfilePath?: string;
  catalogPolicy?: OrgCatalogPolicyDocument;
  catalogPolicyFile?: string;
  apiUrl?: string;
  licenseKey?: string;
  customerId?: string;
  repo?: string;
  inputStream?: Readable;
  outputStream?: Writable;
  stderrStream?: Writable;
  timeoutMs?: number;
}

export interface StdioProxyHandle {
  close: () => Promise<void>;
  waitForExit: () => Promise<number>;
  middleware: ShieldMiddleware;
}

const SAFE_PARENT_ENV_ALLOWLIST = new Set([
  'PATH',
  'HOME',
  'USER',
  'LOGNAME',
  'SHELL',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'TERM',
  'TMPDIR',
  'TEMP',
  'TMP',
  'TZ',
  'SYSTEMROOT',
  'WINDIR',
  'COMSPEC',
  'PATHEXT',
  'APPDATA',
  'LOCALAPPDATA',
  'USERPROFILE',
  'NODE_ENV',
  'NODE_EXTRA_CA_CERTS',
  'SSL_CERT_FILE',
  'SSL_CERT_DIR',
  'NPM_CONFIG_CACHE',
  'XDG_CACHE_HOME',
  'XDG_CONFIG_HOME',
  'XDG_DATA_HOME',
]);

const BLOCKED_LOADER_ENV_VARS = new Set([
  'NODE_OPTIONS',
  'LD_PRELOAD',
  'DYLD_INSERT_LIBRARIES',
  'DYLD_LIBRARY_PATH',
  'PYTHONPATH',
  'BASH_ENV',
  'ENV',
]);

function buildSanitizedChildEnv(
  vaultSecrets: Record<string, string>,
  explicitEnv?: Record<string, string>
): Record<string, string> {
  const safeParentEnv: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (typeof v === 'string' && SAFE_PARENT_ENV_ALLOWLIST.has(k) && !BLOCKED_LOADER_ENV_VARS.has(k.toUpperCase())) {
      safeParentEnv[k] = v;
    }
  }
  const safeVaultSecrets: Record<string, string> = {};
  for (const [k, v] of Object.entries(vaultSecrets || {})) {
    if (typeof v === 'string' && !BLOCKED_LOADER_ENV_VARS.has(k.toUpperCase())) {
      safeVaultSecrets[k] = v;
    }
  }
  const merged: Record<string, string> = {
    ...safeParentEnv,
    ...safeVaultSecrets,
  };
  if (explicitEnv && typeof explicitEnv === 'object') {
    for (const [k, v] of Object.entries(explicitEnv)) {
      if (typeof v === 'string' && !BLOCKED_LOADER_ENV_VARS.has(k.toUpperCase())) {
        merged[k] = v;
      }
    }
  }
  return merged;
}

export function loadToolVetoSecretsEnv(customHomeDir?: string, serverName?: string): Record<string, string> {
  const unscoped: Record<string, string> = {};
  const scoped: Record<string, Record<string, string>> = {};
  try {
    const home = customHomeDir || process.env.HOME || os.homedir();
    const secretsPath = path.join(home, '.toolveto', 'secrets.env');
    if (!fs.existsSync(secretsPath)) return unscoped;
    const raw = fs.readFileSync(secretsPath, 'utf-8');
    let currentSection: string | null = null;
    for (const line of raw.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const sectionMatch = trimmed.match(/^\[([^\]]+)\]$/);
      if (sectionMatch) {
        currentSection = sectionMatch[1].trim();
        if (!scoped[currentSection]) scoped[currentSection] = {};
        continue;
      }
      const m = trimmed.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
      if (!m) continue;
      const key = m[1];
      let val = m[2];
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        try {
          val = val.startsWith('"') ? JSON.parse(val) : val.slice(1, -1);
        } catch {
          val = val.slice(1, -1);
        }
      }
      if (currentSection) {
        scoped[currentSection][key] = val;
      } else {
        unscoped[key] = val;
      }
    }
  } catch {
    // Ignore unreadable secrets vault
  }
  if (serverName && scoped[serverName]) {
    return { ...unscoped, ...scoped[serverName] };
  }
  return unscoped;
}

function resolveSavedCloudCredentials(): { apiUrl?: string; licenseKey?: string; customerId?: string } {
  try {
    const cfgPath = path.join(process.env.HOME || os.homedir(), '.toolveto', 'config.json');
    if (fs.existsSync(cfgPath)) {
      const parsed = JSON.parse(fs.readFileSync(cfgPath, 'utf-8'));
      return {
        apiUrl: typeof parsed.apiUrl === 'string' ? parsed.apiUrl : undefined,
        licenseKey: typeof parsed.token === 'string' ? parsed.token : undefined,
        customerId: typeof parsed.customerId === 'string' ? parsed.customerId : undefined,
      };
    }
  } catch {
    // Ignore unreadable user config
  }
  return {};
}

function resolveDefaultLockfile(explicitPath?: string): Record<string, string> | undefined {
  if (explicitPath) {
    return loadLockfileHashesFromDisk(explicitPath);
  }
  for (const candidate of ['toolveto.lock.json', 'toolveto.lock']) {
    const full = path.resolve(process.cwd(), candidate);
    if (fs.existsSync(full)) {
      const hashes = loadLockfileHashesFromDisk(full);
      if (hashes && Object.keys(hashes).length > 0) return hashes;
    }
  }
  return undefined;
}

export async function startStdioShieldProxy(options: StdioShieldProxyOptions): Promise<StdioProxyHandle> {
  const inputStream = options.inputStream || process.stdin;
  const outputStream = options.outputStream || process.stdout;
  const stderrStream = options.stderrStream || process.stderr;
  const tokenBudget = options.tokenBudget && options.tokenBudget > 0 ? options.tokenBudget : 4000;
  const loopLimit = options.loopLimit && options.loopLimit > 0 ? options.loopLimit : 5;
  const timeoutMs = options.timeoutMs || 30000;

  const savedCloud = resolveSavedCloudCredentials();
  const apiUrl = (
    options.apiUrl ||
    process.env.TOOLVETO_API_URL ||
    savedCloud.apiUrl ||
    'https://toolveto.ai'
  ).replace(/\/+$/, '');
  const licenseKey =
    options.licenseKey || process.env.TOOLVETO_LICENSE_KEY || process.env.TOOLVETO_TOKEN || savedCloud.licenseKey;
  const customerId = options.customerId || process.env.TOOLVETO_CUSTOMER_ID || savedCloud.customerId;
  const upstreamLabel = options.command
    ? path.basename(options.command)
    : options.upstreamUrl || 'stdio-upstream';

  const cloudSyncer = new CloudTelemetrySyncer({
    apiUrl,
    licenseKey,
    customerId,
    repo: options.repo || process.env.TOOLVETO_REPO || `stdio/${upstreamLabel}`,
  });

  const catalogPolicyClient = new OrgCatalogPolicyClient({
    apiUrl,
    licenseKey,
    initialPolicy: options.catalogPolicy,
    policyFile: options.catalogPolicyFile,
  });
  catalogPolicyClient.startPolling();

  const lockfileHashes = resolveDefaultLockfile(options.lockfilePath);
  const middleware = new ShieldMiddleware({
    idempotency: true,
    tokenBudget,
    loopLimit: { count: loopLimit, windowMs: 30000 },
    promptInjectionScan: { action: options.strict ? 'block' : 'sanitize' },
    failClosed: Boolean(options.strict),
    lockfileHashes,
    onListChanged: options.strict ? 'block' : 'revalidate',
    onSpan: (span) => {
      cloudSyncer.recordSpan(upstreamLabel, span);
    },
  });

  const writeDownstream = (msg: Record<string, any> | Array<Record<string, any>>): void => {
    outputStream.write(JSON.stringify(msg) + '\n');
  };

  let child: ChildProcessWithoutNullStreams | null = null;
  let httpSessionId: string | undefined;
  let httpProtocolVersion = '2025-03-26';
  let closed = false;
  let resolveExit!: (code: number) => void;
  const exitPromise = new Promise<number>((resolve) => {
    resolveExit = resolve;
  });

  const pendingUpstreamRequests = new Map<
    string | number,
    {
      resolve: (msg: any) => void;
      reject: (err: Error) => void;
      timer: NodeJS.Timeout;
    }
  >();

  if (options.command) {
    const resolvedCmd =
      process.platform === 'win32' && options.command.toLowerCase() === 'npx'
        ? 'npx.cmd'
        : options.command;
    const vaultSecrets = loadToolVetoSecretsEnv(undefined, options.serverName);

    child = spawn(resolvedCmd, options.args || [], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: buildSanitizedChildEnv(vaultSecrets, options.env),
      ...(process.platform === 'win32' && /\.(cmd|bat)$/i.test(resolvedCmd) ? { shell: true } : {}),
    });

    child.stderr.on('data', (chunk: Buffer) => {
      stderrStream.write(chunk);
    });

    const childRl = readline.createInterface({
      input: child.stdout,
      crlfDelay: Infinity,
    });

    childRl.on('line', (line: string) => {
      const trimmed = line.trim();
      if (!trimmed) return;

      let parsed: any;
      try {
        parsed = JSON.parse(trimmed);
      } catch {
        // Never leak malformed non-JSON stdout from upstream child onto MCP stdio stdout!
        stderrStream.write(`[ToolVeto Shield Upstream stdout] ${trimmed}\n`);
        return;
      }

      if (
        parsed &&
        typeof parsed === 'object' &&
        parsed.id !== undefined &&
        parsed.id !== null &&
        !parsed.method &&
        pendingUpstreamRequests.has(parsed.id)
      ) {
        const pending = pendingUpstreamRequests.get(parsed.id)!;
        clearTimeout(pending.timer);
        pendingUpstreamRequests.delete(parsed.id);
        pending.resolve(parsed);
        return;
      }

      if (parsed && typeof parsed === 'object' && parsed.method === 'notifications/tools/list_changed') {
        const decision = middleware.handleNotification(parsed);
        if (!decision.allowed) {
          return;
        }
      }

      // Pass through upstream notifications or server->client requests (sampling/roots/ping)
      writeDownstream(parsed);
    });

    child.on('error', (err) => {
      stderrStream.write(`[ToolVeto Shield] Failed to spawn '${options.command}': ${err.message}\n`);
      for (const [, pending] of pendingUpstreamRequests) {
        clearTimeout(pending.timer);
        pending.reject(err);
      }
      pendingUpstreamRequests.clear();
      resolveExit(1);
    });

    child.on('close', (code) => {
      for (const [, pending] of pendingUpstreamRequests) {
        clearTimeout(pending.timer);
        pending.reject(new Error(`Upstream MCP process exited with code ${code ?? 0}`));
      }
      pendingUpstreamRequests.clear();
      void cloudSyncer.flush().finally(() => {
        resolveExit(code ?? 0);
      });
    });
  } else if (!options.upstreamUrl) {
    throw new Error('Stdio Shield proxy requires either a child command or --upstream <http-url>');
  }

  const sendToUpstream = async (rpcMsg: Record<string, any>, expectResponse: boolean): Promise<any> => {
    if (child) {
      if (!expectResponse) {
        child.stdin.write(JSON.stringify(rpcMsg) + '\n');
        return undefined;
      }
      return new Promise((resolve, reject) => {
        const reqId = rpcMsg.id;
        const timer = setTimeout(() => {
          pendingUpstreamRequests.delete(reqId);
          reject(new Error(`Upstream stdio request '${String(rpcMsg.method)}' timed out after ${timeoutMs}ms`));
        }, timeoutMs);

        pendingUpstreamRequests.set(reqId, { resolve, reject, timer });
        child!.stdin.write(JSON.stringify(rpcMsg) + '\n', (err) => {
          if (err) {
            clearTimeout(timer);
            pendingUpstreamRequests.delete(reqId);
            reject(err);
          }
        });
      });
    }

    // Remote Streamable HTTP / SSE bridge mode
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      'Mcp-Protocol-Version': httpProtocolVersion,
      ...(options.upstreamHeaders || {}),
    };
    if (httpSessionId) {
      headers['Mcp-Session-Id'] = httpSessionId;
    }

    const res = await fetch(options.upstreamUrl!, {
      method: 'POST',
      headers,
      body: JSON.stringify(rpcMsg),
      redirect: 'error',
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (res.status >= 300 && res.status < 400) {
      throw new Error(`Upstream HTTP redirect (${res.status}) disallowed by SSRF policy`);
    }

    const sid = res.headers.get('mcp-session-id');
    if (sid) {
      httpSessionId = sid;
    }

    if (!expectResponse || res.status === 202 || res.status === 204) {
      await res.text().catch(() => '');
      return undefined;
    }

    const rawText = await res.text();
    if (!res.ok && !rawText.trim()) {
      throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    }
    const parsed = parseGatewayUpstreamBody(rawText, res.headers.get('content-type'), rpcMsg.id);
    if (rpcMsg.method === 'initialize' && parsed?.result?.protocolVersion) {
      httpProtocolVersion = String(parsed.result.protocolVersion);
    }
    return parsed;
  };

  const processSingleClientRpc = async (msg: any): Promise<Record<string, any> | undefined> => {
    if (msg === null || typeof msg !== 'object' || Array.isArray(msg)) {
      return {
        jsonrpc: '2.0',
        id: null,
        error: { code: -32600, message: 'Invalid Request: JSON-RPC message must be an object' },
      };
    }

    const isClientResponse =
      !msg.method &&
      (typeof msg.id === 'string' || typeof msg.id === 'number') &&
      ('result' in msg || 'error' in msg);

    if (isClientResponse) {
      try {
        await sendToUpstream(msg, false);
      } catch (err: any) {
        stderrStream.write(`[ToolVeto Shield] Failed forwarding client response: ${err.message}\n`);
      }
      return undefined;
    }

    if (typeof msg.method !== 'string' || !msg.method.trim()) {
      return {
        jsonrpc: '2.0',
        id: typeof msg.id === 'string' || typeof msg.id === 'number' ? msg.id : null,
        error: { code: -32600, message: 'Invalid Request: JSON-RPC method must be a non-empty string' },
      };
    }

    if (
      msg.id !== undefined &&
      msg.id !== null &&
      typeof msg.id !== 'string' &&
      typeof msg.id !== 'number'
    ) {
      return {
        jsonrpc: '2.0',
        id: null,
        error: { code: -32600, message: 'Invalid Request: JSON-RPC id must be string or number' },
      };
    }

    // Strict JSON-RPC 2.0 notification validation (rejects id: null and smuggled tools/call without id)
    if (msg.id === undefined || msg.id === null) {
      if (msg.id === null || !ALLOWED_CLIENT_NOTIFICATIONS.has(msg.method)) {
        return {
          jsonrpc: '2.0',
          id: null,
          error: {
            code: -32600,
            message: `Invalid Request: Method '${msg.method}' requires a request id or is not an allowlisted client notification`,
          },
        };
      }
      if (msg.method === 'notifications/tools/list_changed') {
        const dec = middleware.handleNotification(msg);
        if (!dec.allowed) {
          return undefined;
        }
      }
      try {
        await sendToUpstream(msg, false);
      } catch (err: any) {
        stderrStream.write(`[ToolVeto Shield] Failed forwarding notification: ${err.message}\n`);
      }
      return undefined;
    }

    if (msg.method === 'tools/list') {
      try {
        const upstreamRes = await sendToUpstream(msg, true);
        const listedTools = upstreamRes?.result?.tools;
        if (Array.isArray(listedTools)) {
          cloudSyncer.reportToolDefinitions(upstreamLabel, listedTools);
          const verifyRes = middleware.verifyToolDefinitions(listedTools);
          if (!verifyRes.valid) {
            if (options.strict) {
              return {
                jsonrpc: '2.0',
                id: msg.id,
                error: {
                  code: -32004,
                  message: `ToolVeto Shield Rug-Pull Blocked: Tool schema drift detected in [${verifyRes.driftedTools.join(', ')}]`,
                  data: { driftedTools: verifyRes.driftedTools },
                },
              };
            }
            const driftedSet = new Set(verifyRes.driftedTools);
            upstreamRes.result.tools = listedTools.filter(
              (t: any) => typeof t?.name === 'string' && !driftedSet.has(t.name)
            );
          }
        }
        return upstreamRes;
      } catch (err: any) {
        return {
          jsonrpc: '2.0',
          id: msg.id ?? null,
          error: { code: -32603, message: `ToolVeto Shield Upstream Error: ${err.message}` },
        };
      }
    }

    if (msg.method === 'tools/call') {
      const toolName = msg.params?.name;
      if (typeof toolName !== 'string' || !toolName.trim()) {
        return {
          jsonrpc: '2.0',
          id: msg.id ?? null,
          error: { code: -32602, message: 'Invalid params: tools/call requires string params.name' },
        };
      }

      const catalogDecision = catalogPolicyClient.evaluate(options.serverName || upstreamLabel, [
        upstreamLabel,
        options.repo || '',
        toolName,
      ]);
      if (!catalogDecision.allowed) {
        return {
          jsonrpc: '2.0',
          id: msg.id ?? null,
          error: {
            code: catalogDecision.code ?? -32004,
            message: catalogDecision.reason || 'ORG_CATALOG_QUARANTINED: Server blocked by enterprise catalog policy',
            data: {
              code: 'ORG_CATALOG_QUARANTINED',
              server: options.serverName || upstreamLabel,
              matchedPattern: catalogDecision.matchedPattern,
            },
          },
        };
      }

      try {
        const shieldedResult = await middleware.intercept(msg, async (rpcReq) => {
          const outboundMsg = {
            jsonrpc: '2.0',
            id: msg.id,
            method: rpcReq.method || 'tools/call',
            params: rpcReq.params,
          };
          const upstreamRes = await sendToUpstream(outboundMsg, true);
          if (upstreamRes?.error) {
            const rpcErr: any = new Error(upstreamRes.error.message || 'Upstream MCP error');
            rpcErr.rpcError = upstreamRes.error;
            throw rpcErr;
          }
          return upstreamRes?.result;
        });

        if (
          options.strict &&
          shieldedResult?._shield &&
          (shieldedResult._shield.rugPullBlocked ||
            shieldedResult._shield.loopChecked ||
            shieldedResult._shield.policyBlocked ||
            (shieldedResult._shield.promptInjectionDetected &&
              shieldedResult._shield.promptInjectionAction === 'block'))
        ) {
          const code = shieldedResult._shield.rugPullBlocked ? -32004 : -32000;
          return {
            jsonrpc: '2.0',
            id: msg.id,
            error: {
              code,
              message: shieldedResult.content?.[0]?.text || 'ToolVeto Shield blocked execution',
            },
          };
        }

        return {
          jsonrpc: '2.0',
          id: msg.id,
          result: shieldedResult,
        };
      } catch (err: any) {
        if (err?.rpcError) {
          return {
            jsonrpc: '2.0',
            id: msg.id,
            error: err.rpcError,
          };
        }
        return {
          jsonrpc: '2.0',
          id: msg.id,
          error: {
            code: -32000,
            message: `ToolVeto Shield Blocked Execution: ${err.message}`,
          },
        };
      }
    }

    // All other JSON-RPC requests (initialize, ping, resources/*, prompts/*)
    try {
      return await sendToUpstream(msg, true);
    } catch (err: any) {
      return {
        jsonrpc: '2.0',
        id: msg.id ?? null,
        error: { code: -32603, message: `ToolVeto Shield Upstream Error: ${err.message}` },
      };
    }
  };

  const handleClientLine = async (line: string): Promise<void> => {
    const trimmed = line.trim();
    if (!trimmed) return;

    let msg: any;
    try {
      msg = JSON.parse(trimmed);
    } catch {
      writeDownstream({
        jsonrpc: '2.0',
        id: null,
        error: { code: -32700, message: 'Parse error: Invalid JSON-RPC frame' },
      });
      return;
    }

    if (msg === null || typeof msg !== 'object') {
      writeDownstream({
        jsonrpc: '2.0',
        id: null,
        error: { code: -32600, message: 'Invalid Request: JSON-RPC payload must be an object or batch array' },
      });
      return;
    }

    if (Array.isArray(msg)) {
      if (msg.length === 0 || msg.length > MAX_JSONRPC_BATCH_SIZE) {
        writeDownstream({
          jsonrpc: '2.0',
          id: null,
          error: {
            code: -32600,
            message:
              msg.length === 0
                ? 'Invalid Request: JSON-RPC batch array must not be empty'
                : `Invalid Request: JSON-RPC batch exceeds maximum size (${MAX_JSONRPC_BATCH_SIZE})`,
          },
        });
        return;
      }
      const batchResponses: Record<string, any>[] = [];
      for (const item of msg) {
        const itemRes = await processSingleClientRpc(item);
        if (itemRes !== undefined) {
          batchResponses.push(itemRes);
        }
      }
      if (batchResponses.length > 0) {
        writeDownstream(batchResponses);
      }
      return;
    }

    const singleRes = await processSingleClientRpc(msg);
    if (singleRes !== undefined) {
      writeDownstream(singleRes);
    }
  };

  const clientRl = readline.createInterface({
    input: inputStream,
    crlfDelay: Infinity,
  });

  const inFlightHandlers = new Set<Promise<void>>();
  clientRl.on('line', (line: string) => {
    const p = handleClientLine(line).finally(() => {
      inFlightHandlers.delete(p);
    });
    inFlightHandlers.add(p);
  });

  const close = async (): Promise<void> => {
    if (closed) return;
    closed = true;
    clientRl.close();
    await Promise.allSettled(Array.from(inFlightHandlers));

    if (child) {
      try {
        child.stdin.end();
      } catch {
        // ignore
      }
      if (child.exitCode === null && !child.killed) {
        child.kill('SIGTERM');
      }
    } else if (options.upstreamUrl && httpSessionId) {
      try {
        await fetch(options.upstreamUrl, {
          method: 'DELETE',
          headers: {
            'Mcp-Session-Id': httpSessionId,
            'Mcp-Protocol-Version': httpProtocolVersion,
            ...(options.upstreamHeaders || {}),
          },
          redirect: 'error',
          signal: AbortSignal.timeout(2000),
        });
      } catch {
        // ignore session teardown failures
      }
    }

    await cloudSyncer.flush();
    if (!child) {
      resolveExit(0);
    }
  };

  clientRl.on('close', () => {
    void close();
  });

  return {
    close,
    waitForExit: () => exitPromise,
    middleware,
  };
}
