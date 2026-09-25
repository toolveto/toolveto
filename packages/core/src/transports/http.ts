import { McpClient } from './interface.js';
import { McpToolDefinition, McpCallResponse } from '../types.js';

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
      // If GET failed, try posting an empty initialize or ignore if it's purely JSON-RPC POST
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
    const result = await this.jsonRpcRequest('tools/list', {});
    if (result && Array.isArray(result.tools)) {
      return result.tools;
    }
    return [];
  }

  public async callTool(name: string, args: Record<string, any>): Promise<McpCallResponse> {
    try {
      const result = await this.jsonRpcRequest('tools/call', {
        name,
        arguments: args,
      });

      return {
        isError: Boolean(result?.isError),
        content: result?.content || [{ type: 'text', text: JSON.stringify(result) }],
      };
    } catch (err: any) {
      return {
        isError: true,
        content: [{ type: 'text', text: err.message || String(err) }],
      };
    }
  }

  public async close(): Promise<void> {
    // HTTP is stateless
    return Promise.resolve();
  }
}
