import * as fs from 'node:fs';
import * as path from 'node:path';

export interface IngestTraceSpan {
  traceId?: string;
  spanId?: string;
  toolName?: string;
  name?: string;
  isError?: boolean;
  durationMs?: number;
  outputTokens?: number;
  arguments?: Record<string, unknown>;
  errorMessage?: string;
}

export interface SynthesizedRegressionCase {
  id: string;
  toolName: string;
  reason: 'ERROR_REPLAY' | 'LATENCY_SPIKE' | 'UNBOUNDED_PAYLOAD';
  checkId: string;
  sampleArguments: Record<string, unknown>;
}

export interface IngestCommandOptions {
  output?: string;
  format?: 'json' | 'text';
  maxLatencyMs?: number;
  maxTokens?: number;
}

export function synthesizeCasesFromTraceSpans(
  spans: IngestTraceSpan[],
  opts: { maxLatencyMs?: number; maxTokens?: number } = {}
): SynthesizedRegressionCase[] {
  const maxLatencyMs = opts.maxLatencyMs ?? 3000;
  const maxTokens = opts.maxTokens ?? 8000;
  const out: SynthesizedRegressionCase[] = [];
  const seen = new Set<string>();

  for (const span of spans) {
    const toolName = String(span.toolName || span.name || 'unknown_tool').trim();
    const isError = Boolean(span.isError);
    const slow = Number(span.durationMs || 0) >= maxLatencyMs;
    const huge = Number(span.outputTokens || 0) >= maxTokens;
    if (!isError && !slow && !huge) continue;

    const reason: SynthesizedRegressionCase['reason'] = isError
      ? 'ERROR_REPLAY'
      : huge
      ? 'UNBOUNDED_PAYLOAD'
      : 'LATENCY_SPIKE';
    const checkId = reason === 'UNBOUNDED_PAYLOAD' ? 'TC-CTX-001' : reason === 'LATENCY_SPIKE' ? 'TC-ERR-001' : 'TC-IDEMP-001';
    const dedupKey = `${toolName}:${reason}`;
    if (seen.has(dedupKey)) continue;
    seen.add(dedupKey);

    out.push({
      id: `synth_${out.length + 1}_${toolName.replace(/[^a-zA-Z0-9_-]/g, '_')}`,
      toolName,
      reason,
      checkId,
      sampleArguments: span.arguments && typeof span.arguments === 'object' ? span.arguments : {},
    });
  }
  return out;
}

export async function ingestCommand(
  traceFile: string,
  options: IngestCommandOptions = {}
): Promise<SynthesizedRegressionCase[]> {
  const resolved = path.resolve(process.cwd(), traceFile);
  if (!fs.existsSync(resolved)) {
    console.error(`\n❌ Trace file not found: ${resolved}\n`);
    process.exitCode = 1;
    return [];
  }
  const raw = fs.readFileSync(resolved, 'utf8').trim();
  const spans: IngestTraceSpan[] = [];
  if (raw.startsWith('[')) {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) spans.push(...parsed);
  } else if (raw.startsWith('{') && !raw.includes('\n{')) {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed.spans)) spans.push(...parsed.spans);
    else if (Array.isArray(parsed.traces)) spans.push(...parsed.traces);
    else spans.push(parsed);
  } else {
    for (const line of raw.split('\n')) {
      const t = line.trim();
      if (!t) continue;
      try {
        spans.push(JSON.parse(t));
      } catch {
        // skip malformed JSONL line
      }
    }
  }

  const synthesized = synthesizeCasesFromTraceSpans(spans, {
    maxLatencyMs: options.maxLatencyMs,
    maxTokens: options.maxTokens,
  });

  const payload = JSON.stringify(
    {
      schemaVersion: 'toolveto-regression-corpus/v1',
      ingestedSpans: spans.length,
      synthesizedCount: synthesized.length,
      cases: synthesized,
    },
    null,
    2
  );

  if (options.output) {
    fs.mkdirSync(path.dirname(path.resolve(process.cwd(), options.output)), { recursive: true });
    fs.writeFileSync(options.output, payload + '\n');
  }

  if (options.format === 'json') {
    console.log(payload);
  } else {
    console.log(`\n✅ Ingested ${spans.length} trace span(s) -> synthesized ${synthesized.length} deterministic regression case(s).`);
    if (options.output) console.log(`   Written to: ${options.output}`);
  }
  return synthesized;
}
