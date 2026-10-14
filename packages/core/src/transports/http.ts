import { McpClient } from './interface.js';
import {
  McpToolDefinition,
  McpCallResponse,
  McpResourceDefinition,
  McpServerCapabilities,
  McpTask,
  LATEST_MCP_PROTOCOL_VERSION,
} from '../types.js';

export interface HttpMcpClientOptions {
  baseUrl: string;
  headers?: Record<string, string>;
  timeoutMs?: number;
}

export class HttpMcpClient implements McpClient {
  private baseUrl: string;
  private headers: Record<string, string>;
  private timeoutMs: number;
  private requestId = 1;
  private protocolVersion: string = LATEST_MCP_PROTOCOL_VERSION;
  private capabilities: McpServerCapabilities = {};

  constructor(options: HttpMcpClientOptions | string) {
    if (typeof options === 'string') {
      this.baseUrl = options;
      this.headers = {};
      this.timeoutMs = 15000;
    } else {
      this.baseUrl = options.baseUrl;
      this.headers = options.headers || {};
      this.timeoutMs = options.timeoutMs || 15000;
    }
  }

  public async connect(): Promise<void> {
    try {
      const res = await this.jsonRpcRequest('server/discover', {
        protocolVersion: this.protocolVersion,
        capabilities: { tools: {}, tasks: { supported: true, inputRequired: true } },
        clientInfo: { name: 'toolveto-harness', version: '0.1.0' },
        _meta: { protocolVersion: this.protocolVersion, client: 'toolveto-harness' },
      });
      if (res?.protocolVersion) {
        this.protocolVersion = res.protocolVersion;
      }
      if (res?.capabilities) {
        this.capabilities = res.capabilities;
      }
    } catch {
      // Ping base URL or /health to ensure remote server is reachable
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.timeoutMs);
        const res = await fetch(this.baseUrl, {
          method: 'GET',
          headers: this.headers,
          signal: controller.signal,
        });
        clearTimeout(timer);
        // Even if 404 or 405 on GET (since MCP is JSON-RPC POST), network connectivity is confirmed
        if (res.status >= 500) {
          throw new Error(`Remote MCP server returned HTTP ${res.status}`);
        }
      } catch (err: any) {
        // If GET failed, ignore if it's purely JSON-RPC POST
      }
    }
  }

  private async jsonRpcRequest(method: string, params: Record<string, any> = {}): Promise<any> {
    const id = this.requestId++;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(this.baseUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...this.headers,
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id,
          method,
          params,
        }),
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (!response.ok) {
        const text = await response.text();
        throw new Error(`HTTP ${response.status}: ${text || response.statusText}`);
      }

      const json = (await response.json()) as any;
      if (json && json.error) {
        throw new Error(`JSON-RPC Error [${json.error.code}]: ${json.error.message}`);
      }

      return json?.result;
    } catch (err: any) {
      clearTimeout(timer);
      throw err;
    }
  }

  public async listTools(): Promise<McpToolDefinition[]> {
    const result = await this.jsonRpcRequest('tools/list', {
      _meta: {
        protocolVersion: this.protocolVersion,
        client: 'toolveto-harness',
      },
    });
    if (result && Array.isArray(result.tools)) {
      return result.tools;
    }
    return [];
  }

  public async listResources(): Promise<McpResourceDefinition[]> {
    try {
      const result = await this.jsonRpcRequest('resources/list', {
        _meta: {
          protocolVersion: this.protocolVersion,
          client: 'toolveto-harness',
        },
      });
      return Array.isArray(result?.resources) ? result.resources : [];
    } catch {
      return [];
    }
  }

  public async readResource(uri: string): Promise<{ contents: Array<{ uri: string; text?: string; blob?: string }> }> {
    const result = await this.jsonRpcRequest('resources/read', {
      uri,
      _meta: {
        protocolVersion: this.protocolVersion,
        client: 'toolveto-harness',
      },
    });
    return {
      contents: Array.isArray(result?.contents) ? result.contents : [],
    };
  }

  public async sendRawRequest(rawJson: string | Record<string, unknown>): Promise<any> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await fetch(this.baseUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...this.headers,
        },
        body: typeof rawJson === 'string' ? rawJson : JSON.stringify(rawJson),
        signal: controller.signal,
      });
      clearTimeout(timer);
      const text = await response.text();
      if (!text || !text.trim()) {
        return undefined;
      }
      try {
        return JSON.parse(text);
      } catch {
        return {
          jsonrpc: '2.0',
          error: {
            code: response.status >= 500 ? -32603 : -32700,
            message: text || response.statusText,
          },
        };
      }
    } catch (err: any) {
      clearTimeout(timer);
      throw err;
    }
  }

  public async callTool(name: string, args: Record<string, any>): Promise<McpCallResponse> {
    try {
      const result = await this.jsonRpcRequest('tools/call', {
        name,
        arguments: args,
        _meta: {
          protocolVersion: this.protocolVersion,
          client: 'toolveto-harness',
        },
      });

      return {
        content: result?.content || [{ type: 'text', text: JSON.stringify(result) }],
        isError: Boolean(result?.isError),
        errorCode: result?.errorCode,
        resultType: result?.resultType || 'complete',
        taskId: result?.taskId,
        _meta: result?._meta,
      };
    } catch (err: any) {
      const isConnectionDrop =
        err.name === 'AbortError' ||
        err.code === 'ECONNREFUSED' ||
        err.code === 'ECONNRESET' ||
        err.message?.includes('fetch failed') ||
        err.message?.includes('dropped transport');

      const isServerCrash =
        isConnectionDrop ||
        err.statusCode >= 500 ||
        err.rpcCode === -32603 ||
        err.rpcCode === -32000 ||
        (typeof err.message === 'string' && (err.message.includes('HTTP 5') || err.message.includes('[-32603]')));

      if (isConnectionDrop || isServerCrash) {
        const panicErr: any = new Error(`MCP HTTP server dropped transport: Process/server panic or crash (${err.message})`);
        panicErr.isPanic = true;
        panicErr.code = err.code || err.rpcCode || err.statusCode || -32603;
        throw panicErr;
      }
      return {
        isError: true,
        errorCode: err.rpcCode || err.statusCode || err.code,
        content: [{ type: 'text', text: err.message || String(err) }],
      };
    }
  }

  public getProtocolVersion(): string {
    return this.protocolVersion;
  }

  public async getCapabilities(): Promise<McpServerCapabilities> {
    return this.capabilities;
  }

  public async getTask(taskId: string): Promise<McpTask | undefined> {
    try {
      const result = await this.jsonRpcRequest('tasks/get', {
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
    try {
      const result = await this.jsonRpcRequest('tasks/update', {
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
        errorCode: err.rpcCode || err.statusCode || err.code,
        content: [{ type: 'text', text: err.message || String(err) }],
      };
    }
  }

  public async cancelTask(taskId: string): Promise<boolean> {
    try {
      const result = await this.jsonRpcRequest('tasks/cancel', {
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
    // HTTP is stateless
    return Promise.resolve();
  }
}
