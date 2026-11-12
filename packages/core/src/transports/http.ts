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
  keepAlive?: boolean;
}

/**
 * Parses either a standard `application/json` body or an MCP Streamable HTTP
 * `text/event-stream` (SSE) payload into the matching JSON-RPC 2.0 response envelope.
 */
export function parseMcpStreamableBody(
  contentType: string | null | undefined,
  rawText: string,
  expectedId?: number | string
): any {
  const trimmed = (rawText || '').trim();
  if (!trimmed) return undefined;

  const normalizedCt = (contentType || '').toLowerCase();
  const looksLikeSse =
    normalizedCt.includes('text/event-stream') ||
    trimmed.startsWith('event:') ||
    trimmed.startsWith('data:');

  if (looksLikeSse) {
    const blocks = trimmed.split(/\r?\n\r?\n/);
    const messages: any[] = [];
    for (const block of blocks) {
      const lines = block.split(/\r?\n/);
      const dataLines: string[] = [];
      for (const line of lines) {
        if (line.startsWith('data:')) {
          dataLines.push(line.slice(5).trimStart());
        }
      }
      if (dataLines.length > 0) {
        const payloadStr = dataLines.join('\n').trim();
        if (payloadStr && payloadStr !== '[DONE]') {
          try {
            const parsed = JSON.parse(payloadStr);
            if (Array.isArray(parsed)) {
              messages.push(...parsed);
            } else {
              messages.push(parsed);
            }
          } catch {
            // Ignore malformed SSE comment/data frames
          }
        }
      }
    }

    if (expectedId !== undefined) {
      const exact = messages.find((m) => m && m.id === expectedId);
      if (exact) return exact;
    }
    const rpcReply = messages.find((m) => m && ('result' in m || 'error' in m));
    if (rpcReply) return rpcReply;
    if (messages.length > 0) return messages[messages.length - 1];
    throw new Error(`Unable to parse JSON-RPC message from SSE stream: ${trimmed.slice(0, 200)}`);
  }

  return JSON.parse(trimmed);
}

export class HttpMcpClient implements McpClient {
  private baseUrl: string;
  private headers: Record<string, string>;
  private timeoutMs: number;
  private keepAlive: boolean;
  private requestId = 1;
  private lastRequestId: number | undefined = undefined;
  private sessionId: string | undefined = undefined;
  private negotiatedProtocolVersion: string | undefined = undefined;
  private protocolVersion: string = LATEST_MCP_PROTOCOL_VERSION;
  private capabilities: McpServerCapabilities = {};
  private connected = false;

  constructor(options: HttpMcpClientOptions | string) {
    if (typeof options === 'string') {
      this.baseUrl = options;
      this.headers = {};
      this.timeoutMs = 15000;
      this.keepAlive = true;
    } else {
      this.baseUrl = options.baseUrl;
      this.headers = options.headers || {};
      this.timeoutMs = options.timeoutMs || 15000;
      this.keepAlive = options.keepAlive !== false;
    }
  }

  private buildRequestHeaders(): Record<string, string> {
    const reqHeaders: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      Connection: this.keepAlive ? 'keep-alive' : 'close',
      ...this.headers,
    };
    if (this.sessionId && !reqHeaders['Mcp-Session-Id'] && !reqHeaders['mcp-session-id']) {
      reqHeaders['Mcp-Session-Id'] = this.sessionId;
    }
    if (
      this.negotiatedProtocolVersion &&
      !reqHeaders['Mcp-Protocol-Version'] &&
      !reqHeaders['mcp-protocol-version']
    ) {
      reqHeaders['Mcp-Protocol-Version'] = this.negotiatedProtocolVersion;
    }
    return reqHeaders;
  }

  public async connect(): Promise<void> {
    if (this.connected) return;

    // 1. Standard MCP Streamable HTTP Handshake (initialize + notifications/initialized)
    try {
      const initRes = await this.jsonRpcRequest('initialize', {
        protocolVersion: '2025-03-26',
        capabilities: {
          tools: {},
        },
        clientInfo: {
          name: 'toolveto-harness',
          version: '0.2.0',
        },
      });
      if (initRes?.protocolVersion) {
        this.protocolVersion = initRes.protocolVersion;
        this.negotiatedProtocolVersion = initRes.protocolVersion;
      }
      if (initRes?.capabilities) {
        this.capabilities = initRes.capabilities;
      }
      await this.sendNotification('notifications/initialized').catch(() => {});
      this.connected = true;
      return;
    } catch (initErr: any) {
      // Only fall back to stateless server/discover if initialize is unsupported (-32601)
      const isMethodNotFound =
        initErr?.rpcCode === -32601 ||
        String(initErr?.message || '').toLowerCase().includes('method not found');
      if (!isMethodNotFound && initErr?.statusCode && initErr.statusCode >= 500) {
        throw initErr;
      }
    }

    // 2. Fallback to stateless server/discover or lightweight reachability check
    try {
      const res = await this.jsonRpcRequest('server/discover', {
        protocolVersion: this.protocolVersion,
        capabilities: { tools: {}, tasks: { supported: true, inputRequired: true } },
        clientInfo: { name: 'toolveto-harness', version: '0.2.0' },
        _meta: { protocolVersion: this.protocolVersion, client: 'toolveto-harness' },
      });
      if (res?.protocolVersion) {
        this.protocolVersion = res.protocolVersion;
      }
      if (res?.capabilities) {
        this.capabilities = res.capabilities;
      }
      this.connected = true;
    } catch {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.timeoutMs);
        const res = await fetch(this.baseUrl, {
          method: 'GET',
          headers: {
            Accept: 'application/json, text/event-stream',
            Connection: this.keepAlive ? 'keep-alive' : 'close',
            ...this.headers,
          },
          keepalive: this.keepAlive,
          signal: controller.signal,
        });
        clearTimeout(timer);
        if (res.status >= 500) {
          throw new Error(`Remote MCP server returned HTTP ${res.status}`);
        }
      } catch {
        // Ignore GET rejection if endpoint is strictly JSON-RPC POST
      }
      this.connected = true;
    }
  }

  private async jsonRpcRequest(method: string, params: Record<string, any> = {}): Promise<any> {
    const id = this.requestId++;
    this.lastRequestId = id;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(this.baseUrl, {
        method: 'POST',
        headers: this.buildRequestHeaders(),
        keepalive: this.keepAlive,
        body: JSON.stringify({
          jsonrpc: '2.0',
          id,
          method,
          params,
        }),
        signal: controller.signal,
      });

      clearTimeout(timer);

      const returnedSessionId =
        response.headers.get('mcp-session-id') || response.headers.get('Mcp-Session-Id');
      if (returnedSessionId) {
        this.sessionId = returnedSessionId;
      }

      const rawText = await response.text();
      if (!response.ok) {
        const httpErr: any = new Error(`HTTP ${response.status}: ${rawText || response.statusText}`);
        httpErr.statusCode = response.status;
        throw httpErr;
      }

      const json = parseMcpStreamableBody(response.headers.get('content-type'), rawText, id);
      if (json && json.error) {
        const rpcErr: any = new Error(`JSON-RPC Error [${json.error.code}]: ${json.error.message}`);
        rpcErr.rpcCode = json.error.code;
        throw rpcErr;
      }

      return json?.result;
    } catch (err: any) {
      clearTimeout(timer);
      throw err;
    }
  }

  public async sendNotification(method: string, params: Record<string, unknown> = {}): Promise<void> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await fetch(this.baseUrl, {
        method: 'POST',
        headers: this.buildRequestHeaders(),
        keepalive: this.keepAlive,
        body: JSON.stringify({
          jsonrpc: '2.0',
          method,
          params,
        }),
        signal: controller.signal,
      });
      clearTimeout(timer);
      const returnedSessionId =
        response.headers.get('mcp-session-id') || response.headers.get('Mcp-Session-Id');
      if (returnedSessionId) {
        this.sessionId = returnedSessionId;
      }
      await response.text().catch(() => '');
    } catch (err) {
      clearTimeout(timer);
      throw err;
    }
  }

  public async listTools(): Promise<McpToolDefinition[]> {
    if (!this.connected) {
      await this.connect();
    }
    const result = await this.jsonRpcRequest('tools/list', {
      _meta: {
        protocolVersion: this.protocolVersion,
        client: 'toolveto-harness',
      },
    });
    if (result && Array.isArray(result.tools)) {
      return result.tools.map((t: any) => {
        const readOnlyHint = t.annotations?.readOnlyHint ?? t.readOnlyHint;
        const destructiveHint = t.annotations?.destructiveHint ?? t.destructiveHint;
        const idempotentHint = t.annotations?.idempotentHint ?? t.idempotentHint;
        const openWorldHint = t.annotations?.openWorldHint ?? t.openWorldHint;
        const inferredMutation =
          t.isMutation ??
          (readOnlyHint === true
            ? false
            : destructiveHint === true ||
              (!t.name.startsWith('get_') &&
                !t.name.startsWith('list_') &&
                !t.name.startsWith('search_') &&
                !t.name.startsWith('read_')));
        return {
          name: t.name,
          description: t.description || '',
          inputSchema: t.inputSchema || { type: 'object', properties: {} },
          outputSchema: t.outputSchema,
          isMutation: inferredMutation,
          idempotentHint,
          readOnlyHint,
          destructiveHint,
          openWorldHint,
          requiresApproval: Boolean(t.requiresApproval),
          tasksSupported: Boolean(t.tasksSupported),
        };
      });
    }
    return [];
  }

  public async listResources(): Promise<McpResourceDefinition[]> {
    if (!this.connected) {
      await this.connect();
    }
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
    if (!this.connected) {
      await this.connect();
    }
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
        headers: this.buildRequestHeaders(),
        keepalive: this.keepAlive,
        body: typeof rawJson === 'string' ? rawJson : JSON.stringify(rawJson),
        signal: controller.signal,
      });
      clearTimeout(timer);
      const text = await response.text();
      if (!text || !text.trim()) {
        return undefined;
      }
      try {
        return parseMcpStreamableBody(response.headers.get('content-type'), text);
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
    if (!this.connected) {
      await this.connect();
    }
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
        err.name === 'TimeoutError' ||
        err.code === 'ABORT_ERR' ||
        err.code === 'ECONNREFUSED' ||
        err.code === 'ECONNRESET' ||
        err.message?.includes('aborted') ||
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

  public getLastRequestId(): number | undefined {
    return this.lastRequestId;
  }

  public getSessionId(): string | undefined {
    return this.sessionId;
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
    if (this.sessionId) {
      const activeSession = this.sessionId;
      this.sessionId = undefined;
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 2000);
        await fetch(this.baseUrl, {
          method: 'DELETE',
          headers: {
            ...this.headers,
            'Mcp-Session-Id': activeSession,
          },
          signal: controller.signal,
        });
        clearTimeout(timer);
      } catch {
        // Ignore session teardown errors
      }
    }
    this.connected = false;
  }
}
