import { spawn, ChildProcess } from 'node:child_process';
import * as readline from 'node:readline';
import { McpClient } from './interface.js';
import {
  McpToolDefinition,
  McpCallResponse,
  McpServerCapabilities,
  McpTask,
  LATEST_MCP_PROTOCOL_VERSION,
} from '../types.js';

export interface StdioOptions {
  command: string;
  args?: string[];
  cwd?: string;
  env?: Record<string, string>;
  timeoutMs?: number;
}

export class StdioMcpClient implements McpClient {
  private childProcess: ChildProcess | null = null;
  private pendingRequests: Map<number, { resolve: (val: any) => void; reject: (err: any) => void }> = new Map();
  private nextId = 1;
  private isInitialized = false;
  private stdoutReader: readline.Interface | null = null;
  private serverErrorLog: string[] = [];
  private serverCapabilities: McpServerCapabilities = {};
  private protocolVersion: string = LATEST_MCP_PROTOCOL_VERSION;

  constructor(private options: StdioOptions) {}

  public async connect(): Promise<void> {
    if (this.childProcess) {
      return;
    }

    const { command, args = [], cwd, env, timeoutMs = 15000 } = this.options;

    return new Promise((resolve, reject) => {
      let resolved = false;

      // Sanitize environment variables passed to untrusted MCP server to prevent secret exfiltration
      const safeEnvKeys = [
        'PATH', 'HOME', 'TMPDIR', 'USER', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TERM',
        'SHELL', 'SYSTEMROOT', 'WINDIR', 'NODE_ENV', 'LOCALAPPDATA', 'APPDATA'
      ];
      const sanitizedEnv: Record<string, string> = {};
      for (const k of safeEnvKeys) {
        if (process.env[k] !== undefined) {
          sanitizedEnv[k] = process.env[k]!;
        }
      }

      this.childProcess = spawn(command, args, {
        cwd,
        env: { ...sanitizedEnv, ...env },
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      this.childProcess.on('error', (err) => {
        if (!resolved) {
          resolved = true;
          reject(new Error(`Failed to spawn MCP server '${command}': ${err.message}`));
        }
      });

      this.childProcess.stderr?.on('data', (chunk) => {
        const text = chunk.toString();
        this.serverErrorLog.push(text);
      });

      this.childProcess.on('exit', (code, signal) => {
        const err = new Error(`MCP server process exited unexpectedly with code ${code}, signal ${signal}. Stderr: ${this.serverErrorLog.slice(-5).join('')}`);
        for (const { reject: pendingReject } of this.pendingRequests.values()) {
          pendingReject(err);
        }
        this.pendingRequests.clear();
      });

      this.stdoutReader = readline.createInterface({
        input: this.childProcess.stdout!,
        terminal: false,
      });

      this.stdoutReader.on('line', (line) => {
        const trimmed = line.trim();
        if (!trimmed) return;
        try {
          const msg = JSON.parse(trimmed);
          if (typeof msg.id === 'number' && this.pendingRequests.has(msg.id)) {
            const { resolve: reqResolve, reject: reqReject } = this.pendingRequests.get(msg.id)!;
            this.pendingRequests.delete(msg.id);
            if (msg.error) {
              reqReject(msg.error);
            } else {
              reqResolve(msg.result);
            }
          }
        } catch {
          // Ignore non-json lines
        }
      });

      // Handshake parameters advertising native 2026-07-28 stateless capabilities
      const handshakeParams = {
        protocolVersion: LATEST_MCP_PROTOCOL_VERSION,
        capabilities: {
          tools: {},
          tasks: { supported: true, inputRequired: true },
        },
        clientInfo: {
          name: 'toolveto-harness',
          version: '0.1.0',
        },
        _meta: {
          protocolVersion: LATEST_MCP_PROTOCOL_VERSION,
          client: 'toolveto-harness',
        },
      };

      // Native 2026-07-28 negotiation: Try server/discover first (stateless protocol)
      this.sendRequest('server/discover', handshakeParams, Math.min(timeoutMs, 2000))
        .then((res) => {
          this.protocolVersion = res?.protocolVersion || LATEST_MCP_PROTOCOL_VERSION;
          this.serverCapabilities = res?.capabilities || {};
          this.isInitialized = true;
          resolved = true;
          resolve();
        })
        .catch(() => {
          // Graceful fallback to initialize for 2024-11-05 / 2025-03-26 or hybrid servers
          this.sendRequest('initialize', handshakeParams, timeoutMs)
            .then((res) => {
              this.protocolVersion = res?.protocolVersion || LATEST_MCP_PROTOCOL_VERSION;
              this.serverCapabilities = res?.capabilities || {};
              this.isInitialized = true;
              this.sendNotification('notifications/initialized').catch(() => {});
              resolved = true;
              resolve();
            })
            .catch((err) => {
              if (!resolved) {
                resolved = true;
                this.close();
                reject(err);
              }
            });
        });
    });
  }

  public async listTools(): Promise<McpToolDefinition[]> {
    if (!this.childProcess) {
      await this.connect();
    }
    const result = await this.sendRequest('tools/list', {
      _meta: {
        protocolVersion: this.protocolVersion,
        client: 'toolveto-harness',
      },
    });
    const tools = result?.tools || [];
    return tools.map((t: any) => ({
      name: t.name,
      description: t.description || '',
      inputSchema: t.inputSchema || { type: 'object', properties: {} },
      outputSchema: t.outputSchema,
      isMutation: t.isMutation ?? (!t.name.startsWith('get_') && !t.name.startsWith('list_') && !t.name.startsWith('search_') && !t.name.startsWith('read_')),
      idempotentHint: t.idempotentHint,
      readOnlyHint: t.readOnlyHint,
      destructiveHint: t.destructiveHint,
      openWorldHint: t.openWorldHint,
      requiresApproval: Boolean(t.requiresApproval),
      tasksSupported: Boolean(t.tasksSupported),
    }));
  }

  public async callTool(name: string, args: Record<string, any> = {}): Promise<McpCallResponse> {
    if (!this.childProcess) {
      await this.connect();
    }
    try {
      const result = await this.sendRequest('tools/call', {
        name,
        arguments: args,
        _meta: {
          protocolVersion: this.protocolVersion,
          client: 'toolveto-harness',
        },
      });
      return {
        content: result?.content || [],
        isError: Boolean(result?.isError),
        errorCode: result?.errorCode,
        resultType: result?.resultType || 'complete',
        taskId: result?.taskId,
        _meta: result?._meta,
      };
    } catch (err: any) {
      const isProcessExit =
        this.childProcess?.exitCode !== null ||
        this.childProcess?.killed ||
        err.message?.includes('exited unexpectedly') ||
        err.message?.includes('dropped transport') ||
        err.message?.includes('not connected');

      const isRpcPanic = err.code === -32603 || err.code === -32000;

      if (isProcessExit || isRpcPanic) {
        const panicErr: any = new Error(`MCP server dropped transport: Process aborting with panic (${err.message || err.code})`);
        panicErr.isPanic = true;
        panicErr.code = err.code || -32603;
        throw panicErr;
      }
      return {
        isError: true,
        errorCode: err.code,
        content: [
          {
            type: 'text',
            text: err.message || JSON.stringify(err),
          },
        ],
      };
    }
  }

  private sendRequest(method: string, params: Record<string, any>, timeoutMs = 10000): Promise<any> {
    return new Promise((resolve, reject) => {
      if (!this.childProcess || !this.childProcess.stdin) {
        return reject(new Error('MCP server process is not connected'));
      }

      const id = this.nextId++;
      const timer = setTimeout(() => {
        if (this.pendingRequests.has(id)) {
          this.pendingRequests.delete(id);
          reject(new Error(`MCP request '${method}' timed out after ${timeoutMs}ms`));
        }
      }, timeoutMs);

      this.pendingRequests.set(id, {
        resolve: (val) => {
          clearTimeout(timer);
          resolve(val);
        },
        reject: (err) => {
          clearTimeout(timer);
          reject(err);
        },
      });

      const payload = JSON.stringify({
        jsonrpc: '2.0',
        id,
        method,
        params,
      }) + '\n';

      this.childProcess.stdin.write(payload, 'utf-8', (err) => {
        if (err) {
          clearTimeout(timer);
          this.pendingRequests.delete(id);
          reject(err);
        }
      });
    });
  }

  public async sendNotification(method: string, params?: Record<string, unknown>): Promise<void> {
    if (!this.childProcess || !this.childProcess.stdin) return;
    const payload = JSON.stringify({
      jsonrpc: '2.0',
      method,
      params,
    }) + '\n';
    return new Promise((res) => {
      this.childProcess?.stdin?.write(payload, 'utf-8', () => res());
    });
  }

  public async getCapabilities(): Promise<McpServerCapabilities> {
    return this.serverCapabilities;
  }

  public getProtocolVersion(): string {
    return this.protocolVersion;
  }

  public async getTask(taskId: string): Promise<McpTask | undefined> {
    if (!this.childProcess) {
      await this.connect();
    }
    try {
      const result = await this.sendRequest('tasks/get', {
        id: taskId,
        _meta: {
          protocolVersion: this.protocolVersion,
          client: 'toolveto-harness',
        },
      });
      return result as McpTask;
    } catch {
      return undefined;
    }
  }

  public async updateTask(taskId: string, input: Record<string, any>): Promise<McpCallResponse> {
    if (!this.childProcess) {
      await this.connect();
    }
    try {
      const result = await this.sendRequest('tasks/update', {
        id: taskId,
        input,
        _meta: {
          protocolVersion: this.protocolVersion,
          client: 'toolveto-harness',
        },
      });
      return {
        content: result?.content || [],
        isError: Boolean(result?.isError),
        errorCode: result?.errorCode,
        resultType: result?.resultType || 'complete',
        taskId: result?.taskId || taskId,
        _meta: result?._meta,
      };
    } catch (err: any) {
      return {
        isError: true,
        errorCode: err.code,
        content: [{ type: 'text', text: err.message || JSON.stringify(err) }],
      };
    }
  }

  public async cancelTask(taskId: string): Promise<boolean> {
    if (!this.childProcess) {
      await this.connect();
    }
    try {
      const result = await this.sendRequest('tasks/cancel', {
        id: taskId,
        _meta: {
          protocolVersion: this.protocolVersion,
          client: 'toolveto-harness',
        },
      });
      return Boolean(result?.success ?? true);
    } catch {
      return false;
    }
  }

  public async close(): Promise<void> {
    if (this.stdoutReader) {
      this.stdoutReader.close();
      this.stdoutReader = null;
    }
    if (this.childProcess) {
      const proc = this.childProcess;
      this.childProcess = null;
      try {
        proc.kill('SIGTERM');
      } catch {
        // Ignore kill errors
      }
    }
  }
}
