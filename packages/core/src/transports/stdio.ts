import { spawn, ChildProcess } from 'node:child_process';
import * as readline from 'node:readline';
import { McpClient } from './interface.js';
import { McpToolDefinition, McpCallResponse } from '../types.js';

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

  constructor(private options: StdioOptions) {}

  public async connect(): Promise<void> {
    if (this.childProcess) {
      return;
    }

    const { command, args = [], cwd, env, timeoutMs = 15000 } = this.options;

    return new Promise((resolve, reject) => {
      let resolved = false;

      this.childProcess = spawn(command, args, {
        cwd,
        env: { ...process.env, ...env },
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

      // Send initialize request
      this.sendRequest('initialize', {
        protocolVersion: '2024-11-05',
        capabilities: {
          tools: {},
        },
        clientInfo: {
          name: 'toolveto-harness',
          version: '0.1.0',
        },
      }, timeoutMs)
        .then(() => {
          this.isInitialized = true;
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
  }

  public async listTools(): Promise<McpToolDefinition[]> {
    if (!this.childProcess) {
      await this.connect();
    }
    const result = await this.sendRequest('tools/list', {});
    const tools = result?.tools || [];
    return tools.map((t: any) => ({
      name: t.name,
      description: t.description || '',
      inputSchema: t.inputSchema || { type: 'object', properties: {} },
      isMutation: t.isMutation ?? (!t.name.startsWith('get_') && !t.name.startsWith('list_') && !t.name.startsWith('search_') && !t.name.startsWith('read_')),
      idempotentHint: t.idempotentHint,
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
      });
      return {
        content: result?.content || [],
        isError: Boolean(result?.isError),
      };
    } catch (err: any) {
      // Wire protocol error / internal crash
      return {
        isError: true,
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
