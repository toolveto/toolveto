import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  runSuite,
  formatTerminalReport,
  StdioMcpClient,
  HttpMcpClient,
  McpToolDefinition,
  McpClient,
} from '@toolveto/core';

export interface CheckCommandOptions {
  withLlm?: boolean;
  json?: boolean;
  timeoutMs?: number;
}

export async function checkCommand(
  targetPath: string,
  options: CheckCommandOptions = {}
): Promise<void> {
  let tools: McpToolDefinition[] = [];
  let client: McpClient | null = null;
  let targetDisplay = targetPath || '.';

  try {
    // 1. Remote Streamable HTTP MCP Server
    if (targetPath && (targetPath.startsWith('http://') || targetPath.startsWith('https://'))) {
      const httpClient = new HttpMcpClient({
        baseUrl: targetPath,
        timeoutMs: options.timeoutMs || 15000,
      });
      await httpClient.connect();
      tools = await httpClient.listTools();
      client = httpClient;
    } else {
      const resolvedTarget = path.resolve(process.cwd(), targetPath || '.');

      if (fs.existsSync(resolvedTarget)) {
        const stat = fs.statSync(resolvedTarget);

        // 2. Direct JSON Schema / Manifest file
        if (stat.isFile() && resolvedTarget.endsWith('.json')) {
          const content = fs.readFileSync(resolvedTarget, 'utf-8');
          const parsed = JSON.parse(content);
          if (Array.isArray(parsed)) {
            tools = parsed;
          } else if (parsed && Array.isArray(parsed.tools)) {
            tools = parsed.tools;
          } else if (parsed && parsed.name && parsed.inputSchema) {
            tools = [parsed];
          }
        }
        // 3. Executable Server script (Node / Python)
        else if (stat.isFile()) {
          let command = 'node';
          let args: string[] = [resolvedTarget];

          if (resolvedTarget.endsWith('.py')) {
            command = 'python3';
          } else {
            command = process.execPath;
          }

          const stdioClient = new StdioMcpClient({
            command,
            args,
            timeoutMs: options.timeoutMs || 15000,
          });
          await stdioClient.connect();
          tools = await stdioClient.listTools();
          client = stdioClient;
        }
        // 4. Directory containing server files or schemas
        else if (stat.isDirectory()) {
          const toolsJson = path.join(resolvedTarget, 'tools.json');
          const mcpJson = path.join(resolvedTarget, 'mcp.json');
          const indexJs = path.join(resolvedTarget, 'index.js');
          const indexMjs = path.join(resolvedTarget, 'index.mjs');

          if (fs.existsSync(toolsJson)) {
            const parsed = JSON.parse(fs.readFileSync(toolsJson, 'utf-8'));
            tools = Array.isArray(parsed) ? parsed : parsed.tools || [];
          } else if (fs.existsSync(mcpJson)) {
            const parsed = JSON.parse(fs.readFileSync(mcpJson, 'utf-8'));
            tools = Array.isArray(parsed) ? parsed : parsed.tools || [];
          } else if (fs.existsSync(indexJs) || fs.existsSync(indexMjs)) {
            const entrypoint = fs.existsSync(indexJs) ? indexJs : indexMjs;
            const stdioClient = new StdioMcpClient({
              command: process.execPath,
              args: [entrypoint],
              timeoutMs: options.timeoutMs || 15000,
            });
            await stdioClient.connect();
            tools = await stdioClient.listTools();
            client = stdioClient;
          }
        }
      }
    }

    // Fallback if no tools were discovered
    if (tools.length === 0) {
      tools = [
        {
          name: 'create_payment',
          description: 'Charges credit card',
          isMutation: true,
          inputSchema: {
            type: 'object',
            properties: {
              amount: { type: 'number' },
              currency: { type: 'string' },
              customer_id: { type: 'string' },
            },
            required: ['amount', 'currency', 'customer_id'],
          },
        },
        {
          name: 'update_appointment',
          description: 'Updates customer appointment date',
          isMutation: true,
          inputSchema: {
            type: 'object',
            properties: {
              appointment_id: { type: 'string' },
              date: { type: 'string', format: 'date' },
            },
            required: ['appointment_id', 'date'],
          },
        },
        {
          name: 'list_invoices',
          description: 'Lists all customer invoices',
          isMutation: false,
          inputSchema: {
            type: 'object',
            properties: {
              customer_id: { type: 'string' },
            },
          },
        },
      ];
    }

    const summary = await runSuite(targetDisplay, tools, {
      client: client || undefined,
      withLlm: options.withLlm,
    });

    if (options.json) {
      console.log(JSON.stringify(summary, null, 2));
    } else {
      console.log(formatTerminalReport(summary));
    }

    if (summary.fatalVetoTriggered) {
      process.exitCode = 1;
    }
  } catch (err: any) {
    console.error(`\n❌ ToolVeto Check Error: ${err.message}\n`);
    process.exitCode = 1;
  } finally {
    if (client) {
      await client.close();
    }
  }
}
