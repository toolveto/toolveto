import { McpToolDefinition, McpCallResponse, McpResourceDefinition, McpServerCapabilities, McpTask } from '../types.js';

export interface McpClient {
  connect(): Promise<void>;
  listTools(): Promise<McpToolDefinition[]>;
  callTool(name: string, args: Record<string, any>): Promise<McpCallResponse>;
  close(): Promise<void>;
  listResources?(): Promise<McpResourceDefinition[]>;
  readResource?(uri: string): Promise<{ contents: Array<{ uri: string; text?: string; blob?: string }> }>;
  sendRawRequest?(rawJson: string | Record<string, unknown>): Promise<any>;
  sendNotification?(method: string, params?: Record<string, unknown>): Promise<void>;
  getCapabilities?(): Promise<McpServerCapabilities>;
  getProtocolVersion?(): string;
  getTask?(taskId: string): Promise<McpTask | undefined>;
  updateTask?(taskId: string, input: Record<string, any>): Promise<McpCallResponse>;
  cancelTask?(taskId: string): Promise<boolean>;
}

