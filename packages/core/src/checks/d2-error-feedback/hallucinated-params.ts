import * as fs from 'node:fs';
import * as path from 'node:path';
import { CheckResult, McpToolDefinition } from '../../types.js';
import { McpClient } from '../../transports/interface.js';

const DEFAULT_INJECTED_PARAMS: Array<{ name: string; value: any }> = [
  { name: 'force', value: true },
  { name: 'verbose', value: 'full' },
  { name: 'dry_run', value: 'yes' },
  { name: 'callback_url', value: 'https://evil-canary.attacker.com/leak' },
  { name: 'format', value: true },
];

export function loadHallucinatedParamsCorpus(): Array<{ name: string; value: any }> {
  const startDirs = [
    typeof __dirname !== 'undefined' ? __dirname : '',
    process.cwd(),
  ].filter(Boolean);

  for (const start of startDirs) {
    let cur = start;
    while (cur && cur !== path.dirname(cur)) {
      const candidate = path.join(cur, 'corpus/published/fixtures/hallucinated-params-baseline.json');
      if (fs.existsSync(candidate)) {
        try {
          const parsed = JSON.parse(fs.readFileSync(candidate, 'utf-8'));
          if (Array.isArray(parsed?.injected_parameters) && parsed.injected_parameters.length > 0) {
            return parsed.injected_parameters;
          }
        } catch {
          break;
        }
      }
      cur = path.dirname(cur);
    }
  }
  return DEFAULT_INJECTED_PARAMS;
}

export async function runHallucinatedParamsCheck(
  tool: McpToolDefinition,
  client?: McpClient
): Promise<CheckResult> {
  const startTime = Date.now();
  const corpusParams = loadHallucinatedParamsCorpus();
  const hallucinatedKeys = corpusParams.map((p) => p.name);

  if (client) {
    const payload: Record<string, any> = {};
    for (const param of corpusParams) {
      payload[param.name] = param.value;
    }

    try {
      const resp = await client.callTool(tool.name, payload);
      // Tool should either ignore safely or return a handled schema rejection
      const text = resp.content?.map((c) => c.text).join('') || '';
      if (text.includes('Traceback') || text.includes('TypeError') || text.includes('-32603')) {
        return {
          checkId: 'TC-FUZZ-002',
          dimension: 'D2',
          tool: tool.name,
          status: 'FAIL',
          severity: 'HIGH',
          description: `Hallucinated parameter attack caused internal error on '${tool.name}'`,
          evidence: { evidenceQuality: 'VERIFIED', details: { injectedKeys: hallucinatedKeys, output: text.slice(0, 150) } },
          fix: {
            summary: "Set 'additionalProperties: false' in schema to safely reject or strip unmodeled arguments",
            applyCommand: 'toolveto fix --apply',
            diffs: [
              {
                language: 'typescript-zod',
                code: `+ .strict() // rejects unexpected keys in Zod`,
              },
            ],
          },
          durationMs: Date.now() - startTime,
        };
      }
    } catch (err: any) {
      const isPanic = Boolean(err.isPanic || err.code === -32603 || err.code === 'PANIC' || err.message?.includes('dropped transport'));
      return {
        checkId: 'TC-FUZZ-002',
        dimension: 'D2',
        tool: tool.name,
        status: 'FAIL',
        severity: isPanic ? 'CRITICAL' : 'HIGH',
        vetoClass: isPanic ? 'VETO_PANIC' : undefined,
        isPanic,
        errorCode: err.code || err.statusCode,
        description: `Hallucinated parameters crashed connection on '${tool.name}': ${err.message}`,
        evidence: { evidenceQuality: 'VERIFIED' },
        durationMs: Date.now() - startTime,
      };
    }
  }

  // Static check: does schema set additionalProperties: false?
  const hasAdditionalPropsFalse = tool.inputSchema?.additionalProperties === false;
  if (!hasAdditionalPropsFalse && !client) {
    return {
      checkId: 'TC-FUZZ-002',
      dimension: 'D2',
      tool: tool.name,
      status: 'WARN',
      severity: 'MEDIUM',
      description: `Tool '${tool.name}' does not specify 'additionalProperties: false', allowing hallucinated LLM arguments through`,
      evidence: { evidenceQuality: 'STATIC-ONLY' },
      fix: {
        summary: "Add 'additionalProperties: false' to inputSchema",
        applyCommand: 'toolveto fix --apply',
        diffs: [
          {
            language: 'json-schema',
            code: `+ "additionalProperties": false`,
          },
        ],
      },
      durationMs: Date.now() - startTime,
    };
  }

  return {
    checkId: 'TC-FUZZ-002',
    dimension: 'D2',
    tool: tool.name,
    status: 'PASS',
    severity: 'MEDIUM',
    description: `Tool '${tool.name}' safely tolerates or rejects hallucinated arguments`,
    evidence: { evidenceQuality: client ? 'VERIFIED' : 'STATIC-ONLY' },
    durationMs: Date.now() - startTime,
  };
}
