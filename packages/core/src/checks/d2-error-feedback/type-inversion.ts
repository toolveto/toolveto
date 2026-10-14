import * as fs from 'node:fs';
import * as path from 'node:path';
import { CheckResult, McpToolDefinition } from '../../types.js';
import { McpClient } from '../../transports/interface.js';

interface TypeInversionVector {
  type: string;
  values: any[];
  expected_recovery_advice?: boolean;
}

const DEFAULT_DATE_VECTORS = ['tomorrow morning', 'next Friday at 3pm', 'yesterday', '2026-13-45'];
const DEFAULT_NUMERIC_VECTORS: any[] = ['invalid_string_fuzz', null, 'NaN', 1e308, -1, ''];

export function loadTypeInversionCorpus(): { dateValues: any[]; numericValues: any[] } {
  const startDirs = [
    typeof __dirname !== 'undefined' ? __dirname : '',
    process.cwd(),
  ].filter(Boolean);

  for (const start of startDirs) {
    let cur = start;
    while (cur && cur !== path.dirname(cur)) {
      const candidate = path.join(cur, 'corpus/published/fixtures/type-inversion-baseline.json');
      if (fs.existsSync(candidate)) {
        try {
          const parsed = JSON.parse(fs.readFileSync(candidate, 'utf-8'));
          const vectors: TypeInversionVector[] = Array.isArray(parsed?.vectors) ? parsed.vectors : [];
          const dateVec = vectors.find((v) => v.type === 'date_natural_language')?.values || DEFAULT_DATE_VECTORS;
          const numVec = vectors.find((v) => v.type === 'numeric_overflow_and_specials')?.values || [];
          return {
            dateValues: dateVec.length > 0 ? dateVec : DEFAULT_DATE_VECTORS,
            numericValues: ['invalid_string_fuzz', ...numVec],
          };
        } catch {
          break;
        }
      }
      cur = path.dirname(cur);
    }
  }
  return { dateValues: DEFAULT_DATE_VECTORS, numericValues: DEFAULT_NUMERIC_VECTORS };
}

export async function runTypeInversionFuzzCheck(
  tool: McpToolDefinition,
  client?: McpClient
): Promise<CheckResult> {
  const startTime = Date.now();
  const properties = tool.inputSchema?.properties || {};
  const corpus = loadTypeInversionCorpus();

  // If live client is available, run active type fuzzing
  if (client) {
    for (const [paramName, schema] of Object.entries(properties)) {
      let fuzzValue: any = null;
      if (schema.type === 'integer' || schema.type === 'number') {
        fuzzValue = corpus.numericValues[0] ?? 'invalid_string_fuzz';
      } else if (schema.type === 'string' && (schema.format === 'date' || schema.format === 'date-time' || paramName.includes('date'))) {
        fuzzValue = corpus.dateValues[0] ?? 'tomorrow morning';
      } else if (schema.type === 'boolean') {
        fuzzValue = 'not_a_bool';
      }

      if (fuzzValue !== null) {
        try {
          const resp = await client.callTool(tool.name, { [paramName]: fuzzValue });
          const text = resp.content?.map((c) => c.text).join('') || '';

          // Check if server leaked raw stack trace or internal panic
          const hasStackTrace = text.includes('Internal error: TypeError') ||
            text.includes('at processTicksAndRejections') ||
            text.includes('at Object.') ||
            text.includes('Traceback (most recent call last)');

          if (hasStackTrace) {
            return {
              checkId: 'TC-FUZZ-001',
              dimension: 'D2',
              tool: tool.name,
              status: 'FAIL',
              severity: 'HIGH',
              description: `Type inversion leak: Tool '${tool.name}' crashed with raw stack trace when fuzzed on parameter '${paramName}'`,
              evidence: {
                evidenceQuality: 'VERIFIED',
                details: {
                  param: paramName,
                  injectedValue: fuzzValue,
                  serverOutputSnippet: text.slice(0, 200),
                },
              },
              fix: {
                summary: `Catch validation error and return structured McpError with actionable advice`,
                applyCommand: 'toolveto fix --apply',
                diffs: [
                  {
                    language: 'typescript-zod',
                    code: `+ if (typeof ${paramName} !== "${schema.type}") {\n+   return { isError: true, content: [{ type: "text", text: "Invalid type for '${paramName}'. Expected ${schema.type}." }] };\n+ }`,
                  },
                ],
              },
              durationMs: Date.now() - startTime,
            };
          }
        } catch (err: any) {
          const isPanic = Boolean(err.isPanic || err.code === -32603 || err.code === 'PANIC' || err.message?.includes('dropped transport'));
          return {
            checkId: 'TC-FUZZ-001',
            dimension: 'D2',
            tool: tool.name,
            status: 'FAIL',
            severity: 'CRITICAL',
            vetoClass: isPanic ? 'VETO_PANIC' : undefined,
            isPanic,
            errorCode: err.code || err.statusCode,
            description: `Type inversion crash: Tool '${tool.name}' dropped transport on fuzzed input: ${err.message}`,
            evidence: {
              evidenceQuality: 'VERIFIED',
              details: { error: err.message },
            },
            durationMs: Date.now() - startTime,
          };
        }
      }
    }
  }

  // Static schema analysis fallback
  const dateParams = Object.entries(properties).filter(([name, schema]) => {
    return name.includes('date') || name.includes('time') || schema.format === 'date-time' || schema.format === 'date';
  });

  if (dateParams.length > 0 && !tool.inputSchema.additionalProperties && !client) {
    const [paramName] = dateParams[0];
    return {
      checkId: 'TC-FUZZ-001',
      dimension: 'D2',
      tool: tool.name,
      status: 'WARN',
      severity: 'HIGH',
      description: `Type inversion contract check: Verify natural language string passed to '${paramName}' returns structured recovery advice`,
      evidence: {
        evidenceQuality: 'STATIC-ONLY',
        details: { param: paramName, expectedContract: 'ISO format validator' },
      },
      durationMs: Date.now() - startTime,
    };
  }

  return {
    checkId: 'TC-FUZZ-001',
    dimension: 'D2',
    tool: tool.name,
    status: 'PASS',
    severity: 'HIGH',
    description: `Fuzz tests on '${tool.name}' parameters conform to schema contracts`,
    evidence: {
      evidenceQuality: client ? 'VERIFIED' : 'STATIC-ONLY',
    },
    durationMs: Date.now() - startTime,
  };
}
