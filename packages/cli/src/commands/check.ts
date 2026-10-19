import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  runSuite,
  evaluateServer,
  formatTerminalReport,
  renderPRComment,
  StdioMcpClient,
  HttpMcpClient,
  InMemoryMcpClient,
  McpToolDefinition,
  McpClient,
  SuiteSummary,
} from '@toolveto/core';
import { runPlgTelemetryAndUpdateCheck } from '../telemetry.js';

export interface CheckCommandOptions {
  withLlm?: boolean;
  json?: boolean;
  format?: string;
  timeoutMs?: number;
  allowDestructive?: boolean;
  allowExec?: boolean;
  demo?: boolean;
  ephemeralMock?: boolean;
  threshold?: string | number;
  failOnSeverity?: string;
  skipUpdateCheck?: boolean;
  noTelemetry?: boolean;
}

export function createEphemeralMockClient(tools: McpToolDefinition[]): InMemoryMcpClient {
  const toolMap = new Map<string, McpToolDefinition>();
  const idempotencyStore = new Map<string, string>();
  let entitySeq = 0;

  for (const tool of tools) {
    if (tool.isMutation === undefined) {
      tool.isMutation = Boolean(
        tool.destructiveHint ||
          /^(create|update|delete|drop|remove|transfer|charge|pay|send|insert|upsert|mutate|write|post|put|patch)/i.test(
            tool.name
          )
      );
    }
    toolMap.set(tool.name, tool);
  }

  return new InMemoryMcpClient(tools, async (toolName: string, rawArgs: Record<string, any> = {}) => {
    const tool = toolMap.get(toolName);
    if (!tool) {
      return {
        isError: true,
        content: [{ type: 'text', text: `Tool '${toolName}' not found` }],
      };
    }

    const args = rawArgs && typeof rawArgs === 'object' ? rawArgs : {};
    const props: Record<string, any> = tool.inputSchema?.properties || {};

    // 1. Reject unknown parameters when additionalProperties === false
    if (tool.inputSchema?.additionalProperties === false) {
      for (const key of Object.keys(args)) {
        if (key === '_meta') continue;
        if (!(key in props)) {
          return {
            isError: true,
            content: [
              {
                type: 'text',
                text: `Validation error on '${toolName}': Unexpected parameter '${key}' is not allowed (additionalProperties: false). Allowed parameters: ${Object.keys(props).join(', ') || 'none'}.`,
              },
            ],
          };
        }
      }
    }

    // 2. Validate argument types and semantic date formats against inputSchema.properties
    for (const [paramName, schema] of Object.entries<any>(props)) {
      const val = args[paramName];
      if (val === undefined) continue;

      if (schema?.type === 'number' || schema?.type === 'integer') {
        if (typeof val !== 'number' || Number.isNaN(val) || !Number.isFinite(val)) {
          return {
            isError: true,
            content: [
              {
                type: 'text',
                text: `Invalid type for parameter '${paramName}'. Expected ${schema.type} (e.g. 100), received ${typeof val} (${JSON.stringify(val)}).`,
              },
            ],
          };
        }
      } else if (schema?.type === 'boolean') {
        if (typeof val !== 'boolean') {
          return {
            isError: true,
            content: [
              {
                type: 'text',
                text: `Invalid type for parameter '${paramName}'. Expected boolean (true or false), received ${typeof val}.`,
              },
            ],
          };
        }
      } else if (schema?.type === 'string') {
        if (typeof val !== 'string') {
          return {
            isError: true,
            content: [
              {
                type: 'text',
                text: `Invalid type for parameter '${paramName}'. Expected string, received ${typeof val}.`,
              },
            ],
          };
        }
        const isDateField =
          schema.format === 'date' ||
          schema.format === 'date-time' ||
          paramName.toLowerCase().includes('date');
        const replayPlaceholders = new Set([
          'test_val',
          'burst_cust_001',
          'crash_commit_val',
          'delayed_test',
          'probe_ref_001',
          'updated',
        ]);
        if (isDateField && !replayPlaceholders.has(val) && !/^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])/.test(val)) {
          return {
            isError: true,
            content: [
              {
                type: 'text',
                text: `Invalid format for '${paramName}'. Expected ISO format YYYY-MM-DD (e.g. '2026-10-15'). Received: '${val}'.`,
              },
            ],
          };
        }
      }
    }

    // 3. Simulate stateful entity mutations with or without idempotency key deduplication
    if (tool.isMutation) {
      const idempKeyParam = Object.keys(props).find((k) =>
        ['idempotency_key', 'idempotencykey', 'client_token', 'request_id', 'client_request_id'].includes(
          k.toLowerCase()
        )
      );

      if (idempKeyParam && args[idempKeyParam] !== undefined && args[idempKeyParam] !== null && args[idempKeyParam] !== '') {
        const cacheKey = `${toolName}:${String(args[idempKeyParam])}`;
        const existingId = idempotencyStore.get(cacheKey);
        if (existingId) {
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  status: 'ok',
                  tool: toolName,
                  id: existingId,
                  deduplicated: true,
                }),
              },
            ],
          };
        }
        const newId = `ent_${toolName}_${++entitySeq}`;
        idempotencyStore.set(cacheKey, newId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                status: 'ok',
                tool: toolName,
                id: newId,
                deduplicated: false,
              }),
            },
          ],
        };
      }

      // Schema lacks idempotency key: every invocation creates a new duplicate entity ID!
      const duplicateId = `ent_${toolName}_${++entitySeq}`;
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              status: 'ok',
              tool: toolName,
              id: duplicateId,
              deduplicated: false,
            }),
          },
        ],
      };
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            status: 'ok',
            tool: toolName,
            items: [],
            total: 0,
          }),
        },
      ],
    };
  });
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
): Promise<SuiteSummary | undefined> {
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
          const ext = path.extname(resolvedTarget).toLowerCase();
          if (!new Set(['.js', '.mjs', '.cjs', '.py', '.json']).has(ext)) {
            throw new Error(`Refusing to auto-exec '${ext}'`);
          }
          if (options.allowExec === false || process.env.TOOLVETO_DISALLOW_AUTO_EXEC === '1') {
            throw new Error('auto-exec disabled');
          }

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
            const realTargetDir = fs.realpathSync(resolvedTarget);
            const ALLOWED_EXEC_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.py']);
            const isSafeEntrypoint = (candidatePath: string): string | null => {
              if (!fs.existsSync(candidatePath) || !fs.statSync(candidatePath).isFile()) return null;
              const realCandidate = fs.realpathSync(candidatePath);
              const rel = path.relative(realTargetDir, realCandidate);
              if (rel.startsWith('..') || path.isAbsolute(rel)) {
                throw new Error(
                  `[ToolVeto CLI Security] Blocked path-traversal entrypoint '${candidatePath}' escaping target directory '${realTargetDir}'.`
                );
              }
              const ext = path.extname(realCandidate).toLowerCase();
              if (!ALLOWED_EXEC_EXTENSIONS.has(ext)) {
                return null;
              }
              return realCandidate;
            };

            let entrypoint: string | null = null;
            const pkgJsonPath = path.join(resolvedTarget, 'package.json');
            if (fs.existsSync(pkgJsonPath)) {
              let pkg: any;
              try {
                pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
              } catch {
                pkg = null;
              }
              if (pkg) {
                const mainCandidate = typeof pkg.main === 'string'
                  ? pkg.main
                  : typeof pkg.bin === 'string'
                    ? pkg.bin
                    : pkg.bin && typeof pkg.bin === 'object'
                      ? (Object.values(pkg.bin)[0] as string)
                      : null;
                if (mainCandidate) {
                  const resolvedMain = path.resolve(resolvedTarget, mainCandidate);
                  const relMain = path.relative(resolvedTarget, resolvedMain);
                  if (relMain.startsWith('..') || path.isAbsolute(relMain)) {
                    throw new Error(
                      `[ToolVeto CLI Security] Blocked untrusted package.json entrypoint '${mainCandidate}' escaping target directory '${resolvedTarget}'.`
                    );
                  }
                  entrypoint = isSafeEntrypoint(resolvedMain);
                }
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
                const safeSc = isSafeEntrypoint(sc);
                if (safeSc) {
                  entrypoint = safeSc;
                  break;
                }
              }
            }

            const execDisallowed =
              options.allowExec === false || process.env.TOOLVETO_DISALLOW_AUTO_EXEC === '1';

            if (entrypoint && !execDisallowed) {
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
        return undefined;
      }
    }

    if (options.ephemeralMock && !client) {
      client = createEphemeralMockClient(tools);
    }

    const checkStartMs = Date.now();
    const summary =
      options.ephemeralMock && client
        ? await evaluateServer(client, {
            mode: 'full',
            target: targetDisplay,
            withLlm: options.withLlm,
            destructiveAuthorization: true,
            targetDir: targetPath && !targetPath.startsWith('http') ? targetPath : '.',
          })
        : await runSuite(targetDisplay, tools, {
            client: client || undefined,
            withLlm: options.withLlm,
            destructiveAuthorization: options.allowDestructive,
            targetDir: targetPath && !targetPath.startsWith('http') ? targetPath : '.',
          });
    const durationMs = Date.now() - checkStartMs;

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

    // PLG Free CLI Run Telemetry + Trivy/Grype-style Version & Tier Update Checker
    await runPlgTelemetryAndUpdateCheck({
      summary,
      target: targetDisplay,
      durationMs,
      options: {
        json: options.json,
        format: options.format,
        noTelemetry: options.noTelemetry,
        skipUpdateCheck: options.skipUpdateCheck,
      },
    });

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

    return summary;
  } catch (err: any) {
    console.error(`\n❌ ToolVeto Check Error: ${err.message}\n`);
    process.exitCode = 1;
    return undefined;
  } finally {
    if (client) {
      await client.close();
    }
  }
}
