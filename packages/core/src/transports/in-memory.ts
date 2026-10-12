import { McpClient } from './interface.js';
import { McpToolDefinition, McpCallResponse } from '../types.js';

export type ToolHandler = (args: Record<string, any>) => Promise<McpCallResponse>;

export class InMemoryMcpClient implements McpClient {
  private tools: Map<string, { definition: McpToolDefinition; handler: ToolHandler }> = new Map();
  private tasks: Map<string, any> = new Map();

  constructor(initialTools: Array<{ definition: McpToolDefinition; handler: ToolHandler }> = []) {
    for (const t of initialTools) {
      this.tools.set(t.definition.name, t);
    }
  }

  public registerTool(definition: McpToolDefinition, handler: ToolHandler): void {
    this.tools.set(definition.name, { definition, handler });
  }

  public registerTask(task: any): void {
    this.tasks.set(task.id, task);
  }

  public async getTask(taskId: string): Promise<any> {
    return this.tasks.get(taskId);
  }

  public async updateTask(taskId: string, input: Record<string, any>): Promise<McpCallResponse> {
    const t = this.tasks.get(taskId);
    if (!t) {
      return { isError: true, content: [{ type: 'text', text: `Task '${taskId}' not found` }] };
    }
    t.status = 'completed';
    t.input = input;
    return { resultType: 'complete', taskId, content: [{ type: 'text', text: 'Task completed' }] };
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
