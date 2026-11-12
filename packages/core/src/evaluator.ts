import * as http from 'node:http';
import {
  McpToolDefinition,
  SuiteSummary,
  CheckResult,
  VetoClass,
  CertificationTier,
  Dimension,
  DimensionalScore,
  StatisticalConfidence,
} from './types.js';
import { McpClient } from './transports/interface.js';
import { runSequentialReplayCheck } from './checks/d1-idempotency/sequential-replay.js';
import { runConcurrentBurstCheck } from './checks/d1-idempotency/concurrent-burst.js';
import { runCrashCommitCheck } from './checks/d1-idempotency/crash-commit.js';
import { runIdempotencyKeyCheck } from './checks/d1-idempotency/idempotency-key.js';
import { runTypeInversionFuzzCheck } from './checks/d2-error-feedback/type-inversion.js';
import { runHallucinatedParamsCheck } from './checks/d2-error-feedback/hallucinated-params.js';
import { runSemanticErrorCheck } from './checks/d2-error-feedback/semantic-error.js';
import { runTokenBudgetCheck } from './checks/d3-lite/token-budget.js';
import { runPaginationSchemaCheck } from './checks/d3-lite/schema-linter.js';
import { runDescriptionClarityCheck } from './checks/d3-lite/description-clarity.js';
import { runAdditionalPropertiesCheck } from './checks/d3-lite/additional-properties.js';
import { runDescriptionAmbiguityCheck, runParamSteerabilityCheck } from './checks/d4-steerability/ambiguity.js';
import { runReadBeforeWritePairingCheck } from './checks/d5-auditability/pairing.js';
import { runDryRunCheck } from './checks/d5-auditability/dry-run.js';
import { runTenantIsolationCheck, runOAuthScopeCheck, runRootsPathTraversalCheck } from './checks/tc-auth.js';
import { runResourceListCheck, runResourceReadCheck, runServerCapabilityCheck } from './checks/resources-coverage.js';
import { runCancellationCheck, runLatencyProfilingCheck } from './checks/cancellation-latency.js';
import { runAnnotationCrossCheck } from './checks/annotation-cross-check.js';
import { runDelayedReplayCheck, runHeterogeneousInterleavingCheck } from './checks/delayed-replay.js';
import { runEnvelopeFuzzCheck } from './checks/envelope-fuzz.js';
import { runTasksExtensionCheck } from './checks/tasks-extension.js';
import { runToolPoisoningCheck, runToolShadowingCheck } from './checks/tool-poisoning.js';
import { runSamplingChaosCheck } from './checks/sampling-chaos.js';
import { runOutputSchemaFidelityCheck } from './checks/output-schema.js';
import { loadToolvetoConfig } from './config.js';

export interface RunSuiteOptions {
  client?: McpClient;
  withLlm?: boolean;
  destructiveAuthorization?: boolean;
  targetDir?: string;
  concurrency?: number;
  bootstrapIterations?: number;
}

export function pLimit(concurrency: number) {
  let activeCount = 0;
  const queue: Array<() => void> = [];

  const next = () => {
    activeCount--;
    const fn = queue.shift();
    if (fn) fn();
  };

  return <T>(fn: () => Promise<T>): Promise<T> =>
    new Promise<T>((resolve, reject) => {
      const run = () => {
        activeCount++;
        fn().then(
          (val) => {
            resolve(val);
            next();
          },
          (err) => {
            reject(err);
            next();
          }
        );
      };

      if (activeCount < concurrency) {
        run();
      } else {
        queue.push(run);
      }
    });
}

export async function runSuite(
  target: string,
  tools: McpToolDefinition[],
  options: RunSuiteOptions = {}
): Promise<SuiteSummary> {
  const startTime = Date.now();
  const results: CheckResult[] = [];
  const { client } = options;
  const config = loadToolvetoConfig(options.targetDir || (target.startsWith('http') ? '.' : target));
  const destructiveAuthorization = options.destructiveAuthorization ?? config.destructiveAuthorization ?? false;
  const limit = pLimit(Math.max(1, options.concurrency ?? 5));

  // Run check batteries across tools with bounded concurrency (pLimit(5) + Promise.allSettled)
  const settledTools = await Promise.allSettled(
    tools.map((tool) =>
      limit(async () => {
        const toolResults: CheckResult[] = [];
        // D1 Checks (guarded by destructiveAuthorization to prevent live corruption)
        const replayCheck = await runSequentialReplayCheck(tool, client, destructiveAuthorization);
        toolResults.push(replayCheck);
        toolResults.push(await runConcurrentBurstCheck(tool, client, 10, destructiveAuthorization));
        toolResults.push(await runCrashCommitCheck(tool, client, destructiveAuthorization));
        toolResults.push(runIdempotencyKeyCheck(tool));
        if (client) {
          toolResults.push(await runDelayedReplayCheck(tool, client, destructiveAuthorization));
          toolResults.push(await runCancellationCheck(tool, client, destructiveAuthorization));
          toolResults.push(await runLatencyProfilingCheck(tool, client, destructiveAuthorization));
        }

        // D2 Checks
        toolResults.push(await runTypeInversionFuzzCheck(tool, client));
        toolResults.push(await runHallucinatedParamsCheck(tool, client, destructiveAuthorization));
        toolResults.push(await runSemanticErrorCheck(tool, client));
        if (client) {
          toolResults.push(await runEnvelopeFuzzCheck(tool, client));
          toolResults.push(await runOutputSchemaFidelityCheck(tool, client));
        }
        toolResults.push(runToolPoisoningCheck(tool));

        // D3 Checks
        toolResults.push(await runTokenBudgetCheck(tool, client));
        toolResults.push(runPaginationSchemaCheck(tool));
        toolResults.push(runDescriptionClarityCheck(tool));
        toolResults.push(runAdditionalPropertiesCheck(tool));

        // D4 Checks (Steerability & Schema Ambiguity & Annotations)
        toolResults.push(runDescriptionAmbiguityCheck(tool, tools));
        toolResults.push(runParamSteerabilityCheck(tool));
        if (client) {
          toolResults.push(await runAnnotationCrossCheck(tool, client, replayCheck.status === 'PASS'));
        }

        // D5 Checks (State auditability, Tenant Isolation, Auth, Roots)
        toolResults.push(runReadBeforeWritePairingCheck(tool, tools));
        toolResults.push(runDryRunCheck(tool));
        toolResults.push(runOAuthScopeCheck(tool));
        if (client) {
          toolResults.push(await runTenantIsolationCheck(tool, client, destructiveAuthorization));
          toolResults.push(await runRootsPathTraversalCheck(tool, client, destructiveAuthorization));
          toolResults.push(await runTasksExtensionCheck(tool, client, destructiveAuthorization));
        }
        return toolResults;
      })
    )
  );

  for (const outcome of settledTools) {
    if (outcome.status === 'fulfilled') {
      results.push(...outcome.value);
    }
  }

  // Multi-tool heterogeneous interleaving & cross-server shadowing checks
  if (client) {
    results.push(await runHeterogeneousInterleavingCheck(tools, client, destructiveAuthorization));
  }
  results.push(runToolShadowingCheck(tools));

  // Resource / Prompt / Capability surface checks
  if (client) {
    if (client.listResources) {
      try {
        const resources = await client.listResources();
        results.push(await runResourceListCheck(resources, client));
        results.push(await runResourceReadCheck(resources, client));
      } catch {
        // Safe fallback
      }
    }
    results.push(await runServerCapabilityCheck(client));
    results.push(await runSamplingChaosCheck(client));
  }

  // Detect prompt injection / exfiltration if live client is available
  const injectionResponsePattern =
    /(?:SYSTEM\s*OVERRIDE|Ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|<system>|<<SYS>>|you\s+are\s+now\s+DAN|disregard\s+(?:all\s+)?(?:previous|prior)\s+instructions)/i;

  if (client) {
    // Ephemeral loopback canary HTTP listener to verify real blind SSRF egress without false-positive error echoes
    const canaryHits = new Set<string>();
    let canaryServer: http.Server | undefined;
    let canaryPort = 0;
    try {
      canaryServer = http.createServer((req, res) => {
        try {
          const reqUrl = new URL(req.url || '/', 'http://127.0.0.1');
          const hitTool = reqUrl.searchParams.get('tool');
          if (hitTool) canaryHits.add(hitTool);
        } catch {
          // ignore
        }
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('canary-exfil-captured');
      });
      await new Promise<void>((resolve) => {
        canaryServer!.listen(0, '127.0.0.1', () => {
          const addr = canaryServer!.address();
          if (addr && typeof addr === 'object') canaryPort = addr.port;
          resolve();
        });
        canaryServer!.once('error', () => resolve());
      });
    } catch {
      canaryServer = undefined;
    }

    try {
      const settledProbes = await Promise.allSettled(
        tools.map((tool) =>
          limit(async () => {
            const probeFindings: CheckResult[] = [];
            const canInvokeTool = !tool.isMutation || destructiveAuthorization;

            if (canInvokeTool) {
              try {
                const probeArgs: Record<string, any> = { input: 'probe_canary_input_001' };
                const schemaProps = tool.inputSchema?.properties || {};
                for (const [k, propSchema] of Object.entries(schemaProps)) {
                  if (propSchema?.type === 'string') {
                    if (propSchema.format === 'date' || k.includes('date')) {
                      probeArgs[k] = '2026-10-15';
                    } else if (k.endsWith('_id') || k === 'id' || k === 'cursor' || k === 'currency' || k.includes('key')) {
                      probeArgs[k] = 'probe_ref_001';
                    } else {
                      probeArgs[k] = 'probe_canary_input_001';
                    }
                  } else if (propSchema?.type === 'number' || propSchema?.type === 'integer') {
                    probeArgs[k] = 1;
                  } else if (propSchema?.type === 'boolean') {
                    probeArgs[k] = true;
                  }
                }

                const resp = await client.callTool(tool.name, probeArgs);
                const text = resp.content?.map((c) => c.text).join('') || '';
                if (!resp.isError && injectionResponsePattern.test(text)) {
                  probeFindings.push({
                    checkId: 'TC-VETO-INJECT-001',
                    dimension: 'D2',
                    tool: tool.name,
                    status: 'FAIL',
                    severity: 'CRITICAL',
                    vetoClass: 'VETO_INJECT',
                    description: `VETO_INJECT: Indirect prompt injection vulnerability detected in tool response`,
                    evidence: {
                      evidenceQuality: 'VERIFIED',
                      details: { leakedPattern: 'Prompt override directive detected in tool output' },
                    },
                    durationMs: 10,
                  });
                }
              } catch {
                // ignore
              }
            }

            // Deterministic SSRF callback probe (strictly gated by canInvokeTool; never triggered on URL validation echoes)
            const props = tool.inputSchema?.properties || {};
            const callbackParam = Object.keys(props).find((k) =>
              ['callback_url', 'webhook', 'webhook_url', 'url', 'target_url', 'notify_url'].includes(k.toLowerCase())
            );
            if (callbackParam && canInvokeTool) {
              let ssrfDetected = false;
              let evidenceUrl = '';
              let loopbackConfirmed = false;

              if (canaryPort > 0) {
                try {
                  const localCanaryUrl = `http://127.0.0.1:${canaryPort}/canary-ssrf-probe?tool=${encodeURIComponent(tool.name)}`;
                  const localResp = await client.callTool(tool.name, { [callbackParam]: localCanaryUrl });
                  const localText = localResp.content?.map((c) => c.text).join('') || '';
                  if (
                    canaryHits.has(tool.name) ||
                    (!localResp.isError &&
                      (localText.includes('canary-exfil-captured') ||
                        localText.includes('ami-id') ||
                        localText.includes('security-credentials')))
                  ) {
                    ssrfDetected = true;
                    evidenceUrl = localCanaryUrl;
                    loopbackConfirmed = canaryHits.has(tool.name);
                  }
                } catch {
                  if (canaryHits.has(tool.name)) {
                    ssrfDetected = true;
                    evidenceUrl = `http://127.0.0.1:${canaryPort}/canary-ssrf-probe`;
                    loopbackConfirmed = true;
                  }
                }
              }

              if (!ssrfDetected) {
                try {
                  const canaryUrl = 'http://canary-ssrf-probe.toolveto.internal/latest/meta-data/';
                  const resp = await client.callTool(tool.name, { [callbackParam]: canaryUrl });
                  const text = resp.content?.map((c) => c.text).join('') || '';
                  if (
                    !resp.isError &&
                    (text.includes('ami-id') ||
                      text.includes('security-credentials') ||
                      text.includes('canary-exfil-captured') ||
                      text.includes('instance-identity') ||
                      text.includes('computeMetadata'))
                  ) {
                    ssrfDetected = true;
                    evidenceUrl = canaryUrl;
                  }
                } catch {
                  // ignore
                }
              }

              if (ssrfDetected) {
                probeFindings.push({
                  checkId: 'TC-VETO-EXFIL-001',
                  dimension: 'D5',
                  tool: tool.name,
                  status: 'FAIL',
                  severity: 'CRITICAL',
                  vetoClass: 'VETO_EXFIL',
                  description: `VETO_EXFIL: SSRF / Exfiltration vulnerability detected in parameter '${callbackParam}'. Server performed unblocked internal network egress.`,
                  evidence: {
                    evidenceQuality: 'VERIFIED',
                    details: { canaryUrl: evidenceUrl, loopbackConfirmed },
                  },
                  durationMs: 10,
                });
              }
            }
            return probeFindings;
          })
        )
      );

      for (const outcome of settledProbes) {
        if (outcome.status === 'fulfilled') {
          results.push(...outcome.value);
        }
      }
    } finally {
      if (canaryServer) {
        await new Promise<void>((resolve) => canaryServer!.close(() => resolve()));
      }
    }
  }

  // Optional Stage-4 LLM Error-Healing Judge (--with-llm)
  let llmTokensUsed = 0;
  let llmJudgeStatus = options.withLlm ? 'skipped:no_api_key_configured' : 'disabled';
  if (options.withLlm) {
    const judgeOutcome = await runOptionalLlmErrorJudge(results);
    llmTokensUsed = judgeOutcome.tokensUsed;
    llmJudgeStatus = judgeOutcome.status;
    if (judgeOutcome.results.length > 0) {
      results.push(...judgeOutcome.results);
    }
  }

  // Calculate Fatal Veto Multiplier (Phi)
  let fatalVetoCode: VetoClass = 'VETO_NONE';
  let phi = 1.0;

  const hasPanic = results.some(
    (r) =>
      r.status === 'FAIL' &&
      (r.isPanic === true ||
       r.vetoClass === 'VETO_PANIC' ||
       r.errorCode === -32603 ||
       r.errorCode === -32000 ||
       r.errorCode === 'ECONNRESET' ||
       r.errorCode === 'ECONNREFUSED' ||
       r.errorCode === 'PANIC' ||
       (r.severity === 'CRITICAL' && (
         r.description.includes('dropped transport') ||
         r.description.includes('Process aborting') ||
         r.description.includes('panic') ||
         r.description.includes('crashed connection') ||
         r.description.includes('crash')
       )))
  );

  const hasInject = results.some(
    (r) =>
      r.status === 'FAIL' &&
      (r.checkId === 'TC-VETO-INJECT-001' ||
       r.checkId === 'TC-SEC-002' ||
       r.checkId === 'TC-SEC-003' ||
       r.description.includes('VETO_INJECT'))
  );

  const hasTenantLeak = results.some(
    (r) => r.checkId === 'TC-AUTH-001' && r.description.includes('VETO_TENANT_LEAK')
  );

  const hasExfil = results.some(
    (r) => r.checkId === 'TC-VETO-EXFIL-001' || r.description.includes('VETO_EXFIL')
  );

  const hasTraversal = results.some(
    (r) => r.checkId === 'TC-AUTH-003' && r.description.includes('VETO_TRAVERSAL')
  );

  const hasContextBomb = results.some(
    (r) =>
      (r.checkId === 'TC-CTX-001' || (r.checkId === 'TC-RES-002' && !r.description.includes('VETO_INJECT'))) &&
      r.status === 'FAIL' &&
      r.severity === 'CRITICAL'
  );

  const hasDataLoss = results.some(
    (r) =>
      hasContextBomb ||
      r.description.includes('VETO_DATALOSS') ||
      (r.severity === 'CRITICAL' && (r.description.includes('bulk delete') || r.description.includes('bulk update') || r.description.includes('bulk send')))
  );

  const idempFailures = results.filter(
    (r) =>
      Boolean(client) &&
      r.evidence?.evidenceQuality === 'VERIFIED' &&
      r.dimension === 'D1' &&
      r.status === 'FAIL' &&
      r.severity === 'CRITICAL' &&
      (r.checkId === 'TC-IDEMP-001' || r.checkId === 'TC-IDEMP-002') &&
      ((r.evidence?.mutationsCreated ?? 0) > 1 || r.description.includes('mutations executed') || r.description.includes('vulnerability'))
  );

  const hasSevereBurst = results.some(
    (r) =>
      Boolean(client) &&
      r.evidence?.evidenceQuality === 'VERIFIED' &&
      r.checkId === 'TC-IDEMP-002' &&
      r.status === 'FAIL' &&
      r.severity === 'CRITICAL' &&
      (r.evidence?.mutationsCreated ?? 0) >= 3
  );

  const hasIdemp = idempFailures.length > 0;

  // Veto Severity Ordering per peer_review:M-12, R-10:
  // INJECT, TENANT_LEAK, EXFIL, TRAVERSAL, and PANIC are catastrophic agent breaches (Phi = 0.0)
  // DATALOSS caps score at Phi = 0.50 (unless destructive unprompted)
  // IDEMP caps score at Phi = 0.70 (single replay double-spend) or Phi = 0.25 (severe concurrent burst)
  if (hasInject) {
    fatalVetoCode = 'VETO_INJECT';
    phi = 0.0;
  } else if (hasTenantLeak) {
    fatalVetoCode = 'VETO_TENANT_LEAK';
    phi = 0.0;
  } else if (hasExfil) {
    fatalVetoCode = 'VETO_EXFIL';
    phi = 0.0;
  } else if (hasTraversal) {
    fatalVetoCode = 'VETO_TRAVERSAL';
    phi = 0.0;
  } else if (hasPanic) {
    fatalVetoCode = 'VETO_PANIC';
    phi = 0.0;
  } else if (hasDataLoss) {
    fatalVetoCode = 'VETO_DATALOSS';
    phi = Math.min(phi, 0.50);
  } else if (hasIdemp) {
    fatalVetoCode = 'VETO_IDEMP';
    phi = Math.min(phi, hasSevereBurst ? 0.25 : 0.70);
  }

  // Calculate dimensional scores
  const calcDimensionScore = (dim: Dimension): number => {
    const dimChecks = results.filter((r) => r.dimension === dim);
    if (dimChecks.length === 0) return 100;
    const passed = dimChecks.filter((r) => r.status === 'PASS').length;
    const warned = dimChecks.filter((r) => r.status === 'WARN').length;
    return Math.round(((passed + warned * 0.5) / dimChecks.length) * 100);
  };

  const d1Score = calcDimensionScore('D1');
  const d2Score = calcDimensionScore('D2');
  const d3Score = calcDimensionScore('D3');
  const d4Score = calcDimensionScore('D4');
  const d5Score = calcDimensionScore('D5');

  // Standard PRD Weights: D1 0.35, D2 0.20, D3 0.20, D4 0.15 (warn-only/lint), D5 0.10
  const dimensionalScores: Record<Dimension, DimensionalScore> = {
    D1: { score: d1Score, weight: 0.35, metrics: {} },
    D2: { score: d2Score, weight: 0.20, metrics: {} },
    D3: { score: d3Score, weight: 0.20, metrics: {} },
    D4: { score: d4Score, weight: 0.15, metrics: {} },
    D5: { score: d5Score, weight: 0.10, metrics: {} },
  };

  const rawWeightedScore =
    d1Score * 0.35 +
    d2Score * 0.20 +
    d3Score * 0.20 +
    d4Score * 0.15 +
    d5Score * 0.10;

  const finalScore = Math.max(0, Math.min(100, Math.round(rawWeightedScore * phi)));

  const criticalFailures = results.filter((r) => r.status === 'FAIL' && r.severity === 'CRITICAL');
  const fatalVetoTriggered = phi < 1.0 || criticalFailures.length > 0;
  if (fatalVetoTriggered && fatalVetoCode === 'VETO_NONE') {
    const firstCrit = criticalFailures[0];
    if (firstCrit?.vetoClass && firstCrit.vetoClass !== 'VETO_NONE') {
      fatalVetoCode = firstCrit.vetoClass;
    } else if (firstCrit?.dimension === 'D1') {
      fatalVetoCode = 'VETO_IDEMP';
    } else if (firstCrit?.dimension === 'D3') {
      fatalVetoCode = 'VETO_DATALOSS';
    }
  }

  // Determine Certification Tier: a server with any Fatal Veto can NEVER earn Bronze/Silver/Gold/Platinum
  let tier: CertificationTier = 'Failed';
  if (!fatalVetoTriggered && phi === 1.0) {
    if (finalScore >= 92 && d1Score >= 90 && d2Score >= 90) {
      tier = 'Platinum';
    } else if (finalScore >= 80 && d1Score >= 75 && d2Score >= 75) {
      tier = 'Gold';
    } else if (finalScore >= 65 && d1Score >= 60) {
      tier = 'Silver';
    } else if (finalScore >= 50) {
      tier = 'Bronze';
    }
  }

  // Statistical confidence calculations (honest empirical sample size n = results.length, B=200 bootstrap CI)
  const nRuns = results.length;
  const pointEstimate = finalScore;
  const B = options.bootstrapIterations ?? 200;
  let ciLow = pointEstimate;
  let ciHigh = pointEstimate;

  if (results.length > 0) {
    const bootstrapScores: number[] = [];
    let seed = 42;
    const lcg = () => {
      seed = (seed * 1664525 + 1013904223) % 4294967296;
      return seed / 4294967296;
    };

    const resLen = results.length;
    for (let b = 0; b < B; b++) {
      let d1T = 0, d1P = 0;
      let d2T = 0, d2P = 0;
      let d3T = 0, d3P = 0;
      let d4T = 0, d4P = 0;
      let d5T = 0, d5P = 0;

      for (let i = 0; i < resLen; i++) {
        const r = results[Math.floor(lcg() * resLen)];
        const val = r.status === 'PASS' ? 1 : r.status === 'WARN' ? 0.5 : 0;
        switch (r.dimension) {
          case 'D1': d1T++; d1P += val; break;
          case 'D2': d2T++; d2P += val; break;
          case 'D3': d3T++; d3P += val; break;
          case 'D4': d4T++; d4P += val; break;
          case 'D5': d5T++; d5P += val; break;
        }
      }

      const bD1 = d1T === 0 ? 100 : Math.round((d1P / d1T) * 100);
      const bD2 = d2T === 0 ? 100 : Math.round((d2P / d2T) * 100);
      const bD3 = d3T === 0 ? 100 : Math.round((d3P / d3T) * 100);
      const bD4 = d4T === 0 ? 100 : Math.round((d4P / d4T) * 100);
      const bD5 = d5T === 0 ? 100 : Math.round((d5P / d5T) * 100);

      const bScore = Math.max(0, Math.min(100, Math.round(
        (bD1 * 0.35 +
         bD2 * 0.20 +
         bD3 * 0.20 +
         bD4 * 0.15 +
         bD5 * 0.10) * phi
      )));
      bootstrapScores.push(bScore);
    }
    bootstrapScores.sort((a, b) => a - b);
    ciLow = Math.round(bootstrapScores[Math.floor(B * 0.025)] * 10) / 10;
    ciHigh = Math.round(bootstrapScores[Math.floor(B * 0.975)] * 10) / 10;
  }

  const certifiedLowerBound = fatalVetoTriggered || fatalVetoCode !== 'VETO_NONE' ? 0 : ciLow;

  const statisticalConfidence: StatisticalConfidence = {
    n: nRuns,
    pointEstimate,
    confidenceInterval95: [ciLow, ciHigh],
    certifiedLowerBound,
  };

  // Per-tool scorecard
  const perToolScorecard: Record<string, { score: number; checksPassed: number; checksFailed: number }> = {};
  for (const tool of tools) {
    const toolChecks = results.filter((r) => r.tool === tool.name);
    const passed = toolChecks.filter((r) => r.status === 'PASS').length;
    const failed = toolChecks.filter((r) => r.status === 'FAIL').length;
    const score = toolChecks.length > 0 ? Math.round((passed / toolChecks.length) * 100) : 100;
    perToolScorecard[tool.name] = { score, checksPassed: passed, checksFailed: failed };
  }

  // Dynamic Loop Protection control status from D2/sampling loop checks
  const loopChecks = results.filter((r) =>
    ['TC-ERR-001', 'TC-FUZZ-001', 'TC-FUZZ-WIRE-001', 'TC-SAMPLING-001'].includes(r.checkId)
  );
  const loopProtectionStatus: 'PASS' | 'FAIL' | 'WARN' = loopChecks.some((r) => r.status === 'FAIL')
    ? 'FAIL'
    : loopChecks.some((r) => r.status === 'WARN')
    ? 'WARN'
    : 'PASS';

  // AIUC-1 Compliance Controls
  const aiuc1Compliance: Record<string, 'PASS' | 'FAIL' | 'WARN'> = {
    'AIUC-1 §4.2 Idempotency': d1Score >= 80 ? 'PASS' : 'FAIL',
    'AIUC-1 §4.5 Error Guidance': d2Score >= 75 ? 'PASS' : 'FAIL',
    'AIUC-1 §5.1 Auth Model & Tenant Isolation': hasTenantLeak ? 'FAIL' : 'PASS',
    'AIUC-1 §6.3 Loop Protection': loopProtectionStatus,
    'OWASP Agentic LLM01 Prompt Injection': hasInject ? 'FAIL' : 'PASS',
    'OWASP Agentic LLM02 Sensitive Information Disclosure': hasExfil ? 'FAIL' : 'PASS',
  };

  const expiresAt = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString();

  const environmentManifest: Record<string, string> = {
    harness: 'toolveto-core-v1.1.0',
    protocolVersion: '2025-03-26',
    nodeVersion: process.version,
    platform: process.platform,
    destructiveAuthorization: String(destructiveAuthorization),
    llmJudge: llmJudgeStatus,
  };

  const passedCount = results.filter((r) => r.status === 'PASS').length;
  const failedCount = results.filter((r) => r.status === 'FAIL').length;
  const warnedCount = results.filter((r) => r.status === 'WARN').length;

  return {
    target,
    totalChecks: results.length,
    passed: passedCount,
    failed: failedCount,
    warned: warnedCount,
    fatalVetoTriggered,
    fatalVetoCode,
    phi,
    score: finalScore,
    tier,
    durationMs: Date.now() - startTime,
    llmTokensUsed,
    dimensionalScores,
    results,
    statisticalConfidence,
    aiuc1Compliance,
    environmentManifest,
    expiresAt,
    perToolScorecard,
  };
}

async function runOptionalLlmErrorJudge(
  existingResults: CheckResult[]
): Promise<{ tokensUsed: number; status: string; results: CheckResult[] }> {
  const customEndpoint = process.env.TOOLVETO_LLM_ENDPOINT;
  const openAiKey = process.env.OPENAI_API_KEY;
  const anthropicKey = process.env.ANTHROPIC_API_KEY;
  const geminiKey = process.env.GEMINI_API_KEY;

  if (!customEndpoint && !openAiKey && !anthropicKey && !geminiKey) {
    return { tokensUsed: 0, status: 'skipped:no_api_key_configured', results: [] };
  }

  const candidateChecks = existingResults
    .filter((r) => r.dimension === 'D2' && (r.status === 'FAIL' || r.status === 'WARN'))
    .slice(0, 5);

  const promptBody =
    candidateChecks.length > 0
      ? `Evaluate whether these MCP tool error findings give an autonomous LLM enough actionable recovery guidance to self-correct without retrying in a loop. Respond strictly as JSON {"actionable": boolean, "score": number, "summary": string}.\nFindings:\n${JSON.stringify(
          candidateChecks.map((c) => ({ tool: c.tool, checkId: c.checkId, description: c.description, details: c.evidence?.details }))
        )}`
      : `Confirm that zero D2 error-ergonomics failures were observed. Respond strictly as JSON {"actionable": true, "score": 100, "summary": "All D2 deterministic checks passed"}.`;

  const startTime = Date.now();
  try {
    let tokensUsed = 0;
    let rawReply = '';
    let providerName = 'custom';

    if (customEndpoint || openAiKey) {
      providerName = customEndpoint ? 'custom-openai-compatible' : 'openai';
      const url = customEndpoint || 'https://api.openai.com/v1/chat/completions';
      const model = process.env.TOOLVETO_LLM_MODEL || 'gpt-4.1-mini';
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (openAiKey) headers['Authorization'] = `Bearer ${openAiKey}`;
      const resp = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          model,
          temperature: 0,
          max_tokens: 256,
          messages: [
            { role: 'system', content: 'You are the ToolVeto Stage-4 E_heal error ergonomics judge. Output valid JSON only.' },
            { role: 'user', content: promptBody },
          ],
        }),
        signal: AbortSignal.timeout(10000),
      });
      if (!resp.ok) {
        return { tokensUsed: 0, status: `error:http_${resp.status}`, results: [] };
      }
      const data: any = await resp.json();
      tokensUsed = Number(data?.usage?.total_tokens ?? ((data?.usage?.prompt_tokens ?? 0) + (data?.usage?.completion_tokens ?? 0))) || 0;
      rawReply = String(data?.choices?.[0]?.message?.content || '');
    } else if (anthropicKey) {
      providerName = 'anthropic';
      const model = process.env.TOOLVETO_LLM_MODEL || 'claude-sonnet-4-6';
      const resp = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': anthropicKey,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model,
          max_tokens: 256,
          messages: [{ role: 'user', content: promptBody }],
        }),
        signal: AbortSignal.timeout(10000),
      });
      if (!resp.ok) {
        return { tokensUsed: 0, status: `error:http_${resp.status}`, results: [] };
      }
      const data: any = await resp.json();
      tokensUsed = Number((data?.usage?.input_tokens ?? 0) + (data?.usage?.output_tokens ?? 0)) || 0;
      rawReply = String(data?.content?.[0]?.text || '');
    } else if (geminiKey) {
      providerName = 'gemini';
      const model = process.env.TOOLVETO_LLM_MODEL || 'gemini-2.5-flash';
      const resp = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(geminiKey)}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            contents: [{ parts: [{ text: promptBody }] }],
            generationConfig: { temperature: 0, maxOutputTokens: 256 },
          }),
          signal: AbortSignal.timeout(10000),
        }
      );
      if (!resp.ok) {
        return { tokensUsed: 0, status: `error:http_${resp.status}`, results: [] };
      }
      const data: any = await resp.json();
      tokensUsed = Number(data?.usageMetadata?.totalTokenCount ?? 0) || 0;
      rawReply = String(data?.candidates?.[0]?.content?.parts?.[0]?.text || '');
    }

    let parsed: { actionable?: boolean; score?: number; summary?: string } = {};
    try {
      const jsonMatch = rawReply.match(/\{[\s\S]*\}/);
      if (jsonMatch) parsed = JSON.parse(jsonMatch[0]);
    } catch {
      parsed = { actionable: candidateChecks.length === 0, summary: rawReply.slice(0, 180) };
    }

    const actionable = parsed.actionable ?? candidateChecks.length === 0;
    return {
      tokensUsed,
      status: `evaluated:${providerName}`,
      results: [
        {
          checkId: 'TC-LLM-HEAL-001',
          dimension: 'D2',
          tool: candidateChecks[0]?.tool || '_suite',
          status: actionable ? 'PASS' : 'WARN',
          severity: actionable ? 'INFO' : 'MEDIUM',
          description: `Stage-4 LLM E_heal Judge (${providerName}): ${parsed.summary || (actionable ? 'Error guidance is actionable for self-correction.' : 'Error responses lack actionable recovery hints.')}`,
          evidence: {
            evidenceQuality: 'VERIFIED',
            details: { provider: providerName, tokensUsed, score: parsed.score ?? (actionable ? 100 : 40) },
          },
          durationMs: Date.now() - startTime,
        },
      ],
    };
  } catch (err: any) {
    return { tokensUsed: 0, status: `error:${err?.message || 'network_failure'}`, results: [] };
  }
}

export interface EvaluateServerOptions extends RunSuiteOptions {
  mode?: 'full' | 'static';
  target?: string;
}

export async function evaluateServer(
  client: McpClient,
  options: EvaluateServerOptions = {}
): Promise<SuiteSummary> {
  await client.connect();
  const tools = await client.listTools();
  const target = options.target || 'ephemeral-mock-server';
  const destructiveAuthorization = options.mode === 'full' ? true : options.destructiveAuthorization;
  return runSuite(target, tools, {
    ...options,
    client,
    destructiveAuthorization,
  });
}
