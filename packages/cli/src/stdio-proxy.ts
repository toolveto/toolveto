import { spawn, ChildProcessWithoutNullStreams } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as readline from 'node:readline';
import { Readable, Writable } from 'node:stream';
import { ShieldMiddleware } from '@toolveto/shield';
import {
  CloudTelemetrySyncer,
  loadLockfileHashesFromDisk,
  parseGatewayUpstreamBody,
} from 'toolveto-gateway';

export interface StdioShieldProxyOptions {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  upstreamUrl?: string;
  upstreamHeaders?: Record<string, string>;
  tokenBudget?: number;
  loopLimit?: number;
  strict?: boolean;
  lockfilePath?: string;
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
  const apiUrl = options.apiUrl || process.env.TOOLVETO_API_URL || savedCloud.apiUrl;
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

  const writeDownstream = (msg: Record<string, any>): void => {
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
    child = spawn(options.command, options.args || [], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, ...(options.env || {}) },
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
        middleware.handleNotification(parsed);
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
      signal: AbortSignal.timeout(timeoutMs),
    });

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

    const isNotification =
      msg && typeof msg === 'object' && typeof msg.method === 'string' && (msg.id === undefined || msg.id === null);
    const isClientResponse =
      msg && typeof msg === 'object' && !msg.method && msg.id !== undefined && ('result' in msg || 'error' in msg);

    if (isNotification || isClientResponse) {
      if (msg.method === 'notifications/tools/list_changed') {
        middleware.handleNotification(msg);
      }
      try {
        await sendToUpstream(msg, false);
      } catch (err: any) {
        stderrStream.write(`[ToolVeto Shield] Failed forwarding notification: ${err.message}\n`);
      }
      return;
    }

    if (msg.method === 'tools/list') {
      try {
        const upstreamRes = await sendToUpstream(msg, true);
        const listedTools = upstreamRes?.result?.tools;
        if (Array.isArray(listedTools)) {
          cloudSyncer.reportToolDefinitions(upstreamLabel, listedTools);
          const verifyRes = middleware.verifyToolDefinitions(listedTools);
          if (!verifyRes.valid && options.strict) {
            writeDownstream({
              jsonrpc: '2.0',
              id: msg.id,
              error: {
                code: -32004,
                message: `ToolVeto Shield Rug-Pull Blocked: Tool schema drift detected in [${verifyRes.driftedTools.join(', ')}]`,
                data: { driftedTools: verifyRes.driftedTools },
              },
            });
            return;
          }
        }
        writeDownstream(upstreamRes);
      } catch (err: any) {
        writeDownstream({
          jsonrpc: '2.0',
          id: msg.id ?? null,
          error: { code: -32603, message: `ToolVeto Shield Upstream Error: ${err.message}` },
        });
      }
      return;
    }

    if (msg.method === 'tools/call') {
      const toolName = msg.params?.name;
      if (typeof toolName !== 'string' || !toolName.trim()) {
        writeDownstream({
          jsonrpc: '2.0',
          id: msg.id ?? null,
          error: { code: -32602, message: 'Invalid params: tools/call requires string params.name' },
        });
        return;
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
          writeDownstream({
            jsonrpc: '2.0',
            id: msg.id,
            error: {
              code,
              message: shieldedResult.content?.[0]?.text || 'ToolVeto Shield blocked execution',
            },
          });
          return;
        }

        writeDownstream({
          jsonrpc: '2.0',
          id: msg.id,
          result: shieldedResult,
        });
      } catch (err: any) {
        if (err?.rpcError) {
          writeDownstream({
            jsonrpc: '2.0',
            id: msg.id,
            error: err.rpcError,
          });
        } else {
          writeDownstream({
            jsonrpc: '2.0',
            id: msg.id,
            error: {
              code: -32000,
              message: `ToolVeto Shield Blocked Execution: ${err.message}`,
            },
          });
        }
      }
      return;
    }

    // All other JSON-RPC requests (initialize, ping, resources/*, prompts/*)
    try {
      const upstreamRes = await sendToUpstream(msg, true);
      if (upstreamRes !== undefined) {
        writeDownstream(upstreamRes);
      }
    } catch (err: any) {
      writeDownstream({
        jsonrpc: '2.0',
        id: msg.id ?? null,
        error: { code: -32603, message: `ToolVeto Shield Upstream Error: ${err.message}` },
      });
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
