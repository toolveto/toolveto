import * as fs from 'node:fs';
import {
  runSuite,
  evaluateServer,
  formatTerminalReport,
  renderPRComment,
  InMemoryMcpClient,
  McpToolDefinition,
  McpClient,
  SuiteSummary,
} from '@toolveto/core';
import {
  runPlgTelemetryAndUpdateCheck,
  isTelemetryDryRun,
  resolveCloudCredentials,
  resolveRepoSlug,
} from '../telemetry.js';
import { discoverToolsFromTarget } from '../discovery.js';

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
  failOnVeto?: boolean;
  upload?: boolean;
  repo?: string;
  apiUrl?: string;
  skipUpdateCheck?: boolean;
  noTelemetry?: boolean;
  telemetryDryRun?: boolean;
}

const DEMO_CHECK_TOOLS: McpToolDefinition[] = [
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
          'probe_canary_input_001',
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

export async function checkCommand(
  targetPath: string,
  options: CheckCommandOptions = {}
): Promise<SuiteSummary | undefined> {
  const { apiUrl, token: cloudToken } = resolveCloudCredentials({ apiUrl: options.apiUrl });

  if (options.upload && !cloudToken) {
    console.error(
      `❌ --upload requires TOOLVETO_LICENSE_KEY or 'npx toolveto login --token <tv_live_...>'\n`
    );
    process.exitCode = 1;
    return undefined;
  }

  let tools: McpToolDefinition[] = [];
  let client: McpClient | null = null;
  const cleanTarget = (targetPath || '.').replace(/^stdio:\/\//i, '');
  const targetDisplay = cleanTarget || '.';

  try {
    const discovered = await discoverToolsFromTarget(targetPath || '.', {
      timeoutMs: options.timeoutMs || 15000,
      allowExec: options.allowExec,
      demo: options.demo,
      keepClientOpen: true,
      demoFallbackTools: DEMO_CHECK_TOOLS,
    });
    tools = discovered.tools;
    client = discovered.client;

    if (tools.length === 0) {
      console.error(`\n❌ Error: No tools discovered at ${targetDisplay}.`);
      console.error(`Please provide a valid MCP server or tool definition, or pass --demo for demonstration mode.\n`);
      process.exitCode = 1;
      return undefined;
    }

    if (options.ephemeralMock && !client) {
      client = createEphemeralMockClient(tools);
    }

    const checkStartMs = Date.now();
    const localTargetDir = cleanTarget && !cleanTarget.startsWith('http') ? cleanTarget : '.';
    const summary =
      options.ephemeralMock && client
        ? await evaluateServer(client, {
            mode: 'full',
            target: targetDisplay,
            withLlm: options.withLlm,
            destructiveAuthorization: true,
            targetDir: localTargetDir,
            sourceFiles: discovered.sourceFiles,
            resourceTemplates: discovered.resourceTemplates,
            prompts: discovered.prompts,
            transportMode: discovered.transportMode,
          })
        : await runSuite(targetDisplay, tools, {
            client: client || undefined,
            withLlm: options.withLlm,
            destructiveAuthorization: options.allowDestructive,
            targetDir: localTargetDir,
            sourceFiles: discovered.sourceFiles,
            resourceTemplates: discovered.resourceTemplates,
            prompts: discovered.prompts,
            transportMode: discovered.transportMode,
          });
    const durationMs = Date.now() - checkStartMs;

    // Cloud Audit Scorecard + Drift Check Upload when authenticated (or explicitly requested via --upload)
    const shouldUploadToCloud =
      Boolean(cloudToken) &&
      (Boolean(options.upload) || (!options.noTelemetry && !isTelemetryDryRun(options)));

    if (shouldUploadToCloud) {
      const resolvedRepo = resolveRepoSlug(targetPath || '.', options.repo);
      const dimensions = {
        d1: summary.dimensionalScores?.D1?.score ?? 0,
        d2: summary.dimensionalScores?.D2?.score ?? 0,
        d3: summary.dimensionalScores?.D3?.score ?? 0,
        d4: summary.dimensionalScores?.D4?.score ?? 0,
        d5: summary.dimensionalScores?.D5?.score ?? 0,
      };
      const authHeaders = {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${cloudToken}`,
        'X-ToolVeto-License': cloudToken,
      };

      try {
        await fetch(`${apiUrl}/api/v1/audits`, {
          method: 'POST',
          headers: authHeaders,
          body: JSON.stringify({
            repo: resolvedRepo,
            serverName: resolvedRepo,
            commitSha: process.env.GITHUB_SHA || process.env.CI_COMMIT_SHA || 'local',
            score: summary.score,
            tier: summary.tier,
            vetoTriggered: Boolean(summary.fatalVetoTriggered),
            phi: summary.phi,
            dimensionalScores: summary.dimensionalScores,
            dimensions,
            results: summary.results,
            summary,
          }),
        });
      } catch {
        // Silently continue if audit endpoint is unreachable
      }

      try {
        await fetch(`${apiUrl}/api/v1/drift/check`, {
          method: 'POST',
          headers: authHeaders,
          body: JSON.stringify({
            repo: resolvedRepo,
            tools,
          }),
        });
      } catch {
        // Silently continue if drift endpoint is unreachable
      }
    }

    if (options.json || options.format === 'json') {
      console.log(JSON.stringify(summary, null, 2));
    } else if (options.format === 'sarif') {
      const sarifReport = {
        $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
        version: '2.1.0',
        runs: [
          {
            tool: {
              driver: {
                name: 'ToolVeto',
                informationUri: 'https://toolveto.ai',
                version: '0.2.0',
                rules: Array.from(new Map(summary.results.map((r) => [r.checkId, r])).values()).map((r) => ({
                  id: r.checkId,
                  name: `${r.dimension}-${r.checkId}`,
                  shortDescription: { text: r.description },
                  fullDescription: { text: r.description },
                  defaultConfiguration: {
                    level: r.severity === 'CRITICAL' || r.severity === 'HIGH' ? 'error' : 'warning',
                  },
                })),
              },
            },
            results: summary.results
              .filter((r) => r.status === 'FAIL' || r.status === 'WARN')
              .map((r) => ({
                ruleId: r.checkId,
                level: r.status === 'FAIL' && (r.severity === 'CRITICAL' || r.severity === 'HIGH') ? 'error' : 'warning',
                message: {
                  text: `[${r.dimension}] Tool '${r.tool}': ${r.description} (Evidence: ${r.evidence.evidenceQuality})`,
                },
                locations: [
                  {
                    physicalLocation: {
                      artifactLocation: {
                        uri: summary.target.startsWith('http') ? 'mcp-tools.json' : summary.target,
                      },
                    },
                  },
                ],
              })),
          },
        ],
      };
      console.log(JSON.stringify(sarifReport, null, 2));
    } else if (options.format === 'github-pr') {
      console.log(renderPRComment(summary));
    } else {
      console.log(formatTerminalReport(summary));
      if (process.env.GITHUB_ACTIONS === 'true') {
        for (const r of summary.results) {
          if (r.status === 'FAIL') {
            const level = r.severity === 'CRITICAL' || r.severity === 'HIGH' ? 'error' : 'warning';
            const cleanMsg = `${r.description} (Evidence: ${r.evidence.evidenceQuality})`.replace(/\r?\n/g, ' ');
            console.log(`::${level} title=${r.checkId} (${r.tool})::${cleanMsg}`);
          }
        }
      }
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
        telemetryDryRun: options.telemetryDryRun,
        apiUrl: options.apiUrl,
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

    if (summary.fatalVetoTriggered && options.failOnVeto !== false) {
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
          (r) => r.status === 'FAIL' && (severityRank[r.severity] || 0) >= minRank
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
