import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  runSuite,
  formatTerminalReport,
  renderPRComment,
  StdioMcpClient,
  HttpMcpClient,
  McpToolDefinition,
  McpClient,
} from '@toolveto/core';

export interface CheckCommandOptions {
  withLlm?: boolean;
  json?: boolean;
  format?: string;
  timeoutMs?: number;
  allowDestructive?: boolean;
  demo?: boolean;
  threshold?: string | number;
  failOnSeverity?: string;
}

function extractToolsFromJson(parsed: any, baseDir: string): McpToolDefinition[] {
  if (Array.isArray(parsed)) {
    return parsed;
  }
  if (parsed && Array.isArray(parsed.tools)) {
    return parsed.tools;
  }
  if (parsed && parsed.name && parsed.inputSchema) {
    return [parsed];
  }
  if (parsed && parsed.mcpServers && typeof parsed.mcpServers === 'object') {
    const collected: McpToolDefinition[] = [];
    for (const [, serverCfg] of Object.entries<any>(parsed.mcpServers)) {
      if (!serverCfg || typeof serverCfg !== 'object') continue;
      if (Array.isArray(serverCfg.tools)) {
        collected.push(...serverCfg.tools);
      } else if (typeof serverCfg.toolsPath === 'string') {
        const tp = path.resolve(baseDir, serverCfg.toolsPath);
        if (fs.existsSync(tp)) {
          try {
            const sub = JSON.parse(fs.readFileSync(tp, 'utf-8'));
            collected.push(...extractToolsFromJson(sub, path.dirname(tp)));
          } catch {
            // Ignore invalid sub-config
          }
        }
      }
    }
    return collected;
  }
  return [];
}

export async function checkCommand(
  targetPath: string,
  options: CheckCommandOptions = {}
): Promise<void> {
  let tools: McpToolDefinition[] = [];
  let client: McpClient | null = null;
  const targetDisplay = targetPath || '.';

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

        // 2. Direct JSON Schema / Manifest / Multi-Server Config file
        if (stat.isFile() && resolvedTarget.endsWith('.json')) {
          const content = fs.readFileSync(resolvedTarget, 'utf-8');
          const parsed = JSON.parse(content);
          tools = extractToolsFromJson(parsed, path.dirname(resolvedTarget));
        }
        // 3. Executable Server script (Node / Python)
        else if (stat.isFile()) {
          let command = process.execPath;
          const args: string[] = [resolvedTarget];

          if (resolvedTarget.endsWith('.py')) {
            command = 'python3';
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
        // 4. Directory containing server files, manifests, or client configs
        else if (stat.isDirectory()) {
          const jsonCandidates = [
            path.join(resolvedTarget, 'tools.json'),
            path.join(resolvedTarget, 'mcp.json'),
            path.join(resolvedTarget, 'schema.json'),
            path.join(resolvedTarget, '.cursor', 'mcp.json'),
            path.join(resolvedTarget, 'claude_desktop_config.json'),
          ];

          for (const candidate of jsonCandidates) {
            if (fs.existsSync(candidate)) {
              const parsed = JSON.parse(fs.readFileSync(candidate, 'utf-8'));
              const extracted = extractToolsFromJson(parsed, path.dirname(candidate));
              if (extracted.length > 0) {
                tools = extracted;
                break;
              }
            }
          }

          if (tools.length === 0) {
            let entrypoint: string | null = null;
            const pkgJsonPath = path.join(resolvedTarget, 'package.json');
            if (fs.existsSync(pkgJsonPath)) {
              try {
                const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
                const mainCandidate = typeof pkg.main === 'string'
                  ? pkg.main
                  : typeof pkg.bin === 'string'
                    ? pkg.bin
                    : pkg.bin && typeof pkg.bin === 'object'
                      ? (Object.values(pkg.bin)[0] as string)
                      : null;
                if (mainCandidate) {
                  const resolvedMain = path.resolve(resolvedTarget, mainCandidate);
                  if (fs.existsSync(resolvedMain) && fs.statSync(resolvedMain).isFile()) {
                    entrypoint = resolvedMain;
                  }
                }
              } catch {
                // Ignore malformed package.json
              }
            }

            if (!entrypoint) {
              const scriptCandidates = [
                path.join(resolvedTarget, 'index.js'),
                path.join(resolvedTarget, 'index.mjs'),
                path.join(resolvedTarget, 'dist', 'index.js'),
                path.join(resolvedTarget, 'build', 'index.js'),
                path.join(resolvedTarget, 'server.py'),
                path.join(resolvedTarget, 'main.py'),
              ];
              for (const sc of scriptCandidates) {
                if (fs.existsSync(sc) && fs.statSync(sc).isFile()) {
                  entrypoint = sc;
                  break;
                }
              }
            }

            if (entrypoint) {
              const command = entrypoint.endsWith('.py') ? 'python3' : process.execPath;
              const stdioClient = new StdioMcpClient({
                command,
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
    }

    // Fallback if no tools were discovered
    if (tools.length === 0) {
      if (options.demo) {
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
      } else {
        console.error(`\n❌ Error: No tools discovered at ${targetDisplay}.`);
        console.error(`Please provide a valid MCP server or tool definition, or pass --demo for demonstration mode.\n`);
        process.exitCode = 1;
        return;
      }
    }

    const summary = await runSuite(targetDisplay, tools, {
      client: client || undefined,
      withLlm: options.withLlm,
      destructiveAuthorization: options.allowDestructive,
      targetDir: targetPath && !targetPath.startsWith('http') ? targetPath : '.',
    });

    // Optional Cloud Telemetry Upload when TOOLVETO_TOKEN is configured
    if (process.env.TOOLVETO_TOKEN) {
      const apiUrl = (process.env.TOOLVETO_API_URL || 'http://localhost:3001').replace(/\/+$/, '');
      try {
        await fetch(`${apiUrl}/api/v1/audits`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${process.env.TOOLVETO_TOKEN}`,
          },
          body: JSON.stringify({
            serverName: summary.target,
            score: summary.score,
            tier: summary.tier,
            phi: summary.phi,
            results: summary.results,
          }),
        });
      } catch {
        // Silently continue if telemetry endpoint is unreachable
      }
    }

    if (options.json || options.format === 'json') {
      console.log(JSON.stringify(summary, null, 2));
    } else if (options.format === 'github-pr') {
      console.log(renderPRComment(summary));
    } else {
      console.log(formatTerminalReport(summary));
    }

    // Automatically append rich PR comment to GitHub Step Summary if running in GitHub Actions
    if (process.env.GITHUB_STEP_SUMMARY) {
      try {
        fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, '\n' + renderPRComment(summary) + '\n');
      } catch {
        // Silently continue if step summary file is not writable
      }
    }

    if (summary.fatalVetoTriggered) {
      process.exitCode = 1;
    }

    if (options.threshold !== undefined) {
      const minScore = Number(options.threshold);
      if (!Number.isNaN(minScore) && summary.score < minScore) {
        process.exitCode = 1;
      }
    }

    if (options.failOnSeverity) {
      const severityRank: Record<string, number> = {
        LOW: 1,
        MEDIUM: 2,
        HIGH: 3,
        CRITICAL: 4,
      };
      const minRank = severityRank[options.failOnSeverity.toUpperCase()];
      if (minRank) {
        const triggered = summary.results.some(
          r => r.status === 'FAIL' && (severityRank[r.severity] || 0) >= minRank
        );
        if (triggered) {
          process.exitCode = 1;
        }
      }
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
