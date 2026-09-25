import { McpToolDefinition, McpCallResponse } from '../types.js';

export interface McpClient {
  connect(): Promise<void>;
  listTools(): Promise<McpToolDefinition[]>;
  callTool(name: string, args: Record<string, any>): Promise<McpCallResponse>;
  close(): Promise<void>;
}
