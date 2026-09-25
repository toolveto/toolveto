import { McpClient } from './interface.js';
import { McpToolDefinition, McpCallResponse } from '../types.js';

export type ToolHandler = (args: Record<string, any>) => Promise<McpCallResponse>;

export class InMemoryMcpClient implements McpClient {
  private tools: Map<string, { definition: McpToolDefinition; handler: ToolHandler }> = new Map();

  constructor(initialTools: Array<{ definition: McpToolDefinition; handler: ToolHandler }> = []) {
    for (const t of initialTools) {
      this.tools.set(t.definition.name, t);
    }
  }

  public registerTool(definition: McpToolDefinition, handler: ToolHandler): void {
    this.tools.set(definition.name, { definition, handler });
  }

  public async connect(): Promise<void> {
    return Promise.resolve();
  }

  public async listTools(): Promise<McpToolDefinition[]> {
    return Array.from(this.tools.values()).map((t) => t.definition);
  }

  public async callTool(name: string, args: Record<string, any>): Promise<McpCallResponse> {
    const tool = this.tools.get(name);
    if (!tool) {
      return {
        isError: true,
        content: [{ type: 'text', text: `Tool '${name}' not found` }],
      };
    }
    try {
      return await tool.handler(args);
    } catch (err: any) {
      return {
        isError: true,
        content: [{ type: 'text', text: err.stack || err.message || String(err) }],
      };
    }
  }

  public async close(): Promise<void> {
    return Promise.resolve();
  }
}
