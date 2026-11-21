import * as crypto from 'node:crypto';
import { CheckResult, McpToolDefinition } from '../../types.js';
import { McpClient } from '../../transports/interface.js';
import { extractEntityId } from '../d1-idempotency/entity-extractor.js';

export interface ReadProbeBinding {
  writeTool: string;
  readTool: string;
  deleteTool?: string;
  entityIdJmesPath?: string;
  readIdParam?: string;
}

export interface CompanionPairingMatch {
  entityName: string;
  readTool: McpToolDefinition | null;
  deleteTool: McpToolDefinition | null;
  matchScore: number;
  sharedIdParam?: string;
}

/**
 * Lightweight deterministic JMESPath evaluator supporting dotted paths,
 * array indexing (`items[0].id`), wildcard projections (`items[*].id`),
 * and `||` fallback chains (`data.id || id || result.entity_id`).
 */
export function evaluateJmesPath(data: unknown, expression: string): unknown {
  if (data === null || data === undefined || !expression.trim()) return undefined;
  const alternatives = expression.split('||').map((s) => s.trim()).filter(Boolean);
  for (const alt of alternatives) {
    const val = evalSinglePath(data, alt);
    if (val !== undefined && val !== null && val !== '') {
      return val;
    }
  }
  return undefined;
}

function evalSinglePath(data: unknown, pathExpr: string): unknown {
  const segments = pathExpr.split('.').map((s) => s.trim()).filter(Boolean);
  let current: any = data;
  for (const seg of segments) {
    if (current === null || current === undefined) return undefined;
    const wildcardMatch = /^([a-zA-Z0-9_-]*)\[\*\]$/.exec(seg);
    if (wildcardMatch) {
      const key = wildcardMatch[1];
      const arr = key ? current[key] : current;
      if (!Array.isArray(arr)) return undefined;
      current = arr;
      continue;
    }
    const indexMatch = /^([a-zA-Z0-9_-]*)\[(\d+)\]$/.exec(seg);
    if (indexMatch) {
      const key = indexMatch[1];
      const idx = Number(indexMatch[2]);
      const arr = key ? current[key] : current;
      if (!Array.isArray(arr)) return undefined;
      current = arr[idx];
      continue;
    }
    if (Array.isArray(current)) {
      current = current.map((el) => (el && typeof el === 'object' ? el[seg] : undefined)).filter((v) => v !== undefined);
      continue;
    }
    if (typeof current === 'object') {
      current = current[seg];
    } else {
      return undefined;
    }
  }
  return current;
}

function normalizeEntityStem(name: string): string {
  return name
    .toLowerCase()
    .replace(/^(create|update|delete|remove|set|modify|post|add|upsert|patch|get|read|inspect|find|list|fetch|describe)_/, '')
    .replace(/s$/, '');
}

function extractIdParams(tool: McpToolDefinition): string[] {
  const props = Object.keys(tool.inputSchema?.properties || {});
  return props.filter((k) => /(^id$|_id$|id$)/i.test(k));
}

/**
 * Bipartite schema-AST pairing: matches mutating tool T_w against companion
 * read tool T_r (and optional delete tool T_d) using both entity stems AND
 * shared schema identifier properties.
 */
export function findCompanionTools(
  tool: McpToolDefinition,
  allTools: McpToolDefinition[],
  explicitBinding?: ReadProbeBinding
): CompanionPairingMatch {
  const entityName = tool.name.replace(/^(create_|update_|delete_|set_|modify_|post_|add_|upsert_|patch_)/, '');
  const stem = normalizeEntityStem(tool.name);
  const writeIdParams = new Set(extractIdParams(tool).map((p) => p.toLowerCase()));

  if (explicitBinding) {
    const readTool = allTools.find((t) => t.name === explicitBinding.readTool) || null;
    const deleteTool = explicitBinding.deleteTool
      ? allTools.find((t) => t.name === explicitBinding.deleteTool) || null
      : null;
    if (readTool) {
      return {
        entityName,
        readTool,
        deleteTool,
        matchScore: 100,
        sharedIdParam: explicitBinding.readIdParam || extractIdParams(readTool)[0],
      };
    }
  }

  let bestRead: McpToolDefinition | null = null;
  let bestScore = 0;
  let bestSharedParam: string | undefined;

  for (const candidate of allTools) {
    if (candidate.name === tool.name || candidate.isMutation) continue;
    const qLower = candidate.name.toLowerCase();
    const qStem = normalizeEntityStem(candidate.name);
    const candIds = extractIdParams(candidate);
    let score = 0;

    if (
      qLower === `get_${entityName}` ||
      qLower === `read_${entityName}` ||
      qLower === `inspect_${entityName}` ||
      qLower === `find_${entityName}` ||
      qLower === `list_${entityName}s` ||
      qLower === `get_${entityName}s`
    ) {
      score += 70;
    } else if (stem && qStem && (qStem === stem || qLower.includes(stem))) {
      score += 45;
    }

    const sharedParam = candIds.find(
      (p) =>
        writeIdParams.has(p.toLowerCase()) ||
        p.toLowerCase() === `${stem}_id` ||
        p.toLowerCase() === `${stem}id` ||
        p.toLowerCase() === 'id'
    );
    if (sharedParam) {
      score += 30;
    }

    if (score > bestScore) {
      bestScore = score;
      bestRead = candidate;
      bestSharedParam = sharedParam || candIds[0];
    }
  }

  const deleteTool =
    allTools.find((t) => {
      if (t.name === tool.name) return false;
      const l = t.name.toLowerCase();
      return l === `delete_${entityName}` || l === `remove_${entityName}` || (stem && l === `delete_${stem}`);
    }) || null;

  return {
    entityName,
    readTool: bestScore >= 45 ? bestRead : null,
    deleteTool,
    matchScore: bestScore,
    sharedIdParam: bestSharedParam,
  };
}

function safeParseToolResponse(res: { content?: Array<{ text?: string }> }): unknown {
  const text = res.content?.map((c) => c.text || '').join('') || '';
  try {
    return JSON.parse(text);
  } catch {
    return { rawText: text };
  }
}

function buildSyntheticMutationArgs(tool: McpToolDefinition, marker: string): Record<string, unknown> {
  const props = tool.inputSchema?.properties || {};
  const args: Record<string, unknown> = {};
  for (const [k, p] of Object.entries(props)) {
    const lower = k.toLowerCase();
    if (lower.includes('idemp') || lower.includes('request_id')) {
      args[k] = `tv_probe_${marker}`;
    } else if (p.type === 'number' || p.type === 'integer') {
      args[k] = 42;
    } else if (p.type === 'boolean') {
      args[k] = true;
    } else if (p.type === 'string') {
      args[k] = `tv_probe_${marker}`;
    }
  }
  return args;
}

/**
 * Live Tri-Phase Read-Probe Engine (PAT-03):
 * S_0 pre-read -> synthetic mutate -> JMESPath K_entity extraction ->
 * progressive-backoff post-read S_1 (100ms, 250ms, 500ms, 1000ms) ->
 * field-level delta verification catching silent 200-OK write drops / mocks ->
 * automated companion delete cleanup!
 */
export async function runTriPhaseReadProbeCheck(
  tool: McpToolDefinition,
  allTools: McpToolDefinition[],
  client: McpClient,
  options: {
    binding?: ReadProbeBinding;
    backoffScheduleMs?: number[];
  } = {}
): Promise<CheckResult> {
  const startTime = Date.now();
  const match = findCompanionTools(tool, allTools, options.binding);
  if (!match.readTool) {
    return runReadBeforeWritePairingCheck(tool, allTools);
  }

  const readTool = match.readTool;
  const readIdParam = options.binding?.readIdParam || match.sharedIdParam || 'id';
  const jmesExpr = options.binding?.entityIdJmesPath || 'id || entity_id || data.id || result.id';
  const marker = crypto.randomBytes(4).toString('hex');
  const mutationArgs = buildSyntheticMutationArgs(tool, marker);
  const schedule = options.backoffScheduleMs || [100, 250, 500, 1000];

  let extractedEntityId: string | null = null;
  try {
    // Phase 1: S_0 pre-read baseline
    const preReadRes = await client.callTool(readTool.name, { [readIdParam]: `nonexistent_${marker}` }).catch(() => null);
    const s0 = preReadRes ? safeParseToolResponse(preReadRes) : null;

    // Phase 2: Synthetic mutation call
    const writeRes = await client.callTool(tool.name, mutationArgs);
    if (writeRes.isError) {
      return {
        checkId: 'TC-PAIR-001',
        dimension: 'D5',
        tool: tool.name,
        status: 'WARN',
        severity: 'MEDIUM',
        description: `Tri-phase read-probe skipped: mutation '${tool.name}' rejected synthetic payload`,
        evidence: {
          evidenceQuality: 'PARTIAL',
          details: { companionReadTool: readTool.name },
        },
        durationMs: Date.now() - startTime,
      };
    }

    const writeParsed = safeParseToolResponse(writeRes);
    const jmesVal = evaluateJmesPath(writeParsed, jmesExpr);
    extractedEntityId =
      (typeof jmesVal === 'string' || typeof jmesVal === 'number' ? String(jmesVal) : null) ||
      extractEntityId(writeParsed);

    if (!extractedEntityId) {
      return {
        checkId: 'TC-PAIR-001',
        dimension: 'D5',
        tool: tool.name,
        status: 'FAIL',
        severity: 'HIGH',
        description: `State auditability failure: Mutation '${tool.name}' returned 200 OK without an extractable entity identifier for post-write verification via '${readTool.name}'`,
        evidence: {
          evidenceQuality: 'VERIFIED',
          details: { companionReadTool: readTool.name, jmesPath: jmesExpr },
        },
        durationMs: Date.now() - startTime,
      };
    }

    // Phase 3: Progressive-backoff S_1 post-read & field-level delta (S_1 - S_0)
    let stateVerified = false;
    let lastS1: unknown = null;
    for (const delayMs of schedule) {
      if (delayMs > 0) {
        await new Promise((r) => setTimeout(r, delayMs));
      }
      const postRes = await client.callTool(readTool.name, { [readIdParam]: extractedEntityId });
      if (postRes.isError) continue;
      lastS1 = safeParseToolResponse(postRes);
      const s1Str = JSON.stringify(lastS1);
      const s0Str = JSON.stringify(s0);
      const foundEntity =
        s1Str.includes(extractedEntityId) || s1Str.includes(`tv_probe_${marker}`);
      const notFoundSignal = /\b(not[_\s-]?found|null|missing|404)\b/i.test(s1Str) && !s1Str.includes(`tv_probe_${marker}`);
      if (foundEntity && !notFoundSignal && s1Str !== s0Str) {
        stateVerified = true;
        break;
      }
    }

    if (!stateVerified) {
      return {
        checkId: 'TC-PAIR-001',
        dimension: 'D5',
        tool: tool.name,
        status: 'FAIL',
        severity: 'CRITICAL',
        vetoClass: 'VETO_DATALOSS',
        description: `Silent 200-OK write drop / stubbed mock detected: '${tool.name}' claimed success (entity '${extractedEntityId}'), but post-write read-probe '${readTool.name}' never observed state delta S_1 - S_0`,
        evidence: {
          requestsSent: 2 + schedule.length,
          evidenceQuality: 'VERIFIED',
          details: {
            companionReadTool: readTool.name,
            extractedEntityId,
            jmesPath: jmesExpr,
            backoffScheduleMs: schedule,
            lastReadResponse: lastS1,
          },
        },
        fix: {
          summary: `Ensure '${tool.name}' durably commits state before returning 200 OK so '${readTool.name}' observes the written entity`,
          applyCommand: 'toolveto fix --apply',
          diffs: [
            {
              language: 'typescript-zod',
              code: `+ // Await durable commit before returning entity ID\n+ const committed = await repo.insertAndFlush(args);\n+ return { content: [{ type: "text", text: JSON.stringify(committed) }] };`,
            },
          ],
        },
        durationMs: Date.now() - startTime,
      };
    }

    return {
      checkId: 'TC-PAIR-001',
      dimension: 'D5',
      tool: tool.name,
      status: 'PASS',
      severity: 'LOW',
      description: `Live tri-phase read-probe verified: '${tool.name}' state delta S_1 - S_0 confirmed via '${readTool.name}' (entity '${extractedEntityId}')`,
      evidence: {
        requestsSent: 3,
        evidenceQuality: 'VERIFIED',
        details: {
          companionReadTool: readTool.name,
          extractedEntityId,
          cleanupTool: match.deleteTool?.name,
        },
      },
      durationMs: Date.now() - startTime,
    };
  } finally {
    // Automated companion delete cleanup so synthetic probe entities do not pollute state
    if (extractedEntityId && match.deleteTool) {
      const delIdParam = extractIdParams(match.deleteTool)[0] || readIdParam;
      await client.callTool(match.deleteTool.name, { [delIdParam]: extractedEntityId }).catch(() => undefined);
    }
  }
}

export function runReadBeforeWritePairingCheck(
  tool: McpToolDefinition,
  allTools: McpToolDefinition[],
  binding?: ReadProbeBinding
): CheckResult {
  const startTime = Date.now();

  if (!tool.isMutation) {
    return {
      checkId: 'TC-PAIR-001',
      dimension: 'D5',
      tool: tool.name,
      status: 'PASS',
      severity: 'LOW',
      description: `Query tool '${tool.name}' is an inspection tool`,
      evidence: { evidenceQuality: 'STATIC-ONLY' },
      durationMs: Date.now() - startTime,
    };
  }

  const match = findCompanionTools(tool, allTools, binding);

  if (!match.readTool) {
    return {
      checkId: 'TC-PAIR-001',
      dimension: 'D5',
      tool: tool.name,
      status: 'FAIL',
      severity: 'HIGH',
      description: `State auditability blind-write violation: Mutation tool '${tool.name}' lacks companion query tool ('get_${match.entityName}' or 'read_${match.entityName}'). Agents cannot verify pre/post state changes`,
      evidence: {
        evidenceQuality: 'STATIC-ONLY',
        details: { targetEntity: match.entityName, expectedCompanion: `get_${match.entityName}` },
      },
      fix: {
        summary: `Expose a companion read-only query tool 'get_${match.entityName}' accepting primary entity ID`,
        applyCommand: 'toolveto fix --apply',
        diffs: [
          {
            language: 'typescript-zod',
            code: `+ // Define companion inspection query tool:\n+ server.tool("get_${match.entityName}", { ${match.entityName}_id: z.string() }, async ({ ${match.entityName}_id }) => {\n+   return { content: [{ type: "text", text: JSON.stringify(await db.get(${match.entityName}_id)) }] };\n+ });`,
          },
        ],
      },
      durationMs: Date.now() - startTime,
    };
  }

  return {
    checkId: 'TC-PAIR-001',
    dimension: 'D5',
    tool: tool.name,
    status: 'PASS',
    severity: 'LOW',
    description: `Read-before-write inspection companion '${match.readTool.name}' verified for '${tool.name}'`,
    evidence: {
      evidenceQuality: 'STATIC-ONLY',
      details: {
        companionReadTool: match.readTool.name,
        companionDeleteTool: match.deleteTool?.name,
        matchScore: match.matchScore,
      },
    },
    durationMs: Date.now() - startTime,
  };
}
