export * from './types.js';
export * from './transports/interface.js';
export * from './transports/stdio.js';
export * from './transports/in-memory.js';
export * from './transports/http.js';
export * from './checks/d1-idempotency/sequential-replay.js';
export * from './checks/d1-idempotency/concurrent-burst.js';
export * from './checks/d1-idempotency/idempotency-key.js';
export * from './checks/d1-idempotency/crash-commit.js';
export * from './checks/d1-idempotency/entity-extractor.js';
export * from './checks/d2-error-feedback/type-inversion.js';
export * from './checks/d2-error-feedback/hallucinated-params.js';
export * from './checks/d2-error-feedback/semantic-error.js';
export * from './checks/d3-lite/token-budget.js';
export * from './checks/d3-lite/schema-linter.js';
export * from './checks/d3-lite/description-clarity.js';
export * from './checks/d3-lite/additional-properties.js';
export * from './checks/d4-steerability/ambiguity.js';
export * from './checks/d5-auditability/pairing.js';
export * from './checks/d5-auditability/dry-run.js';
export * from './checks/tc-auth.js';
export * from './checks/resources-coverage.js';
export * from './checks/cancellation-latency.js';
export * from './checks/annotation-cross-check.js';
export * from './checks/delayed-replay.js';
export * from './checks/envelope-fuzz.js';
export * from './checks/tasks-extension.js';
export * from './checks/tool-poisoning.js';
export * from './config.js';
export * from './reporters/terminal.js';
export * from './reporters/github-pr-comment.js';
export * from './evaluator.js';

import {
  McpToolDefinition,
  SuiteSummary,
  CheckResult,
  Dimension,
  VetoClass,
  CertificationTier,
} from './types.js';
import { runIdempotencyKeyCheck } from './checks/d1-idempotency/idempotency-key.js';
import { runPaginationSchemaCheck } from './checks/d3-lite/schema-linter.js';
import { runDescriptionClarityCheck } from './checks/d3-lite/description-clarity.js';
import { runAdditionalPropertiesCheck } from './checks/d3-lite/additional-properties.js';
import { runDescriptionAmbiguityCheck, runParamSteerabilityCheck } from './checks/d4-steerability/ambiguity.js';
import { runReadBeforeWritePairingCheck } from './checks/d5-auditability/pairing.js';
import { runDryRunCheck } from './checks/d5-auditability/dry-run.js';
import { runOAuthScopeCheck } from './checks/tc-auth.js';
import { runToolPoisoningCheck, runToolShadowingCheck } from './checks/tool-poisoning.js';

/**
 * Synchronous static check suite runner across an array of McpToolDefinitions.
 */
export function runSuiteOnTools(
  targetOrTools: string | McpToolDefinition[],
  maybeTools?: McpToolDefinition[]
): SuiteSummary {
  const target = typeof targetOrTools === 'string' ? targetOrTools : 'static-tools-suite';
  const tools = Array.isArray(targetOrTools) ? targetOrTools : (maybeTools || []);
  const startTime = Date.now();
  const results: CheckResult[] = [];

  for (const tool of tools) {
    // D1 Static Check
    results.push(runIdempotencyKeyCheck(tool));
    // D2 Static Check
    results.push(runToolPoisoningCheck(tool));
    // D3 Static Checks
    results.push(runPaginationSchemaCheck(tool));
    results.push(runDescriptionClarityCheck(tool));
    results.push(runAdditionalPropertiesCheck(tool));
    // D4 Static Checks
    results.push(runDescriptionAmbiguityCheck(tool, tools));
    results.push(runParamSteerabilityCheck(tool));
    // D5 Static Checks
    results.push(runReadBeforeWritePairingCheck(tool, tools));
    results.push(runDryRunCheck(tool));
    results.push(runOAuthScopeCheck(tool));
  }

  results.push(runToolShadowingCheck(tools));

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

  let fatalVetoCode: VetoClass = 'VETO_NONE';
  let phi = 1.0;

  const hasInject = results.some(
    (r) => r.status === 'FAIL' && (r.vetoClass === 'VETO_INJECT' || r.description.includes('VETO_INJECT'))
  );
  if (hasInject) {
    fatalVetoCode = 'VETO_INJECT';
    phi = 0.0;
  }

  const rawWeightedScore =
    d1Score * 0.35 +
    d2Score * 0.20 +
    d3Score * 0.20 +
    d4Score * 0.15 +
    d5Score * 0.10;

  const finalScore = Math.max(0, Math.min(100, Math.round(rawWeightedScore * phi)));

  let tier: CertificationTier = 'Failed';
  if (phi === 1.0) {
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

  const passed = results.filter((r) => r.status === 'PASS').length;
  const failed = results.filter((r) => r.status === 'FAIL').length;
  const warned = results.filter((r) => r.status === 'WARN').length;
  const fatalVetoTriggered = phi < 1.0 || results.some((r) => r.status === 'FAIL' && r.severity === 'CRITICAL');

  return {
    target,
    totalChecks: results.length,
    passed,
    failed,
    warned,
    fatalVetoTriggered,
    fatalVetoCode,
    phi,
    score: finalScore,
    tier,
    durationMs: Math.max(1, Date.now() - startTime),
    llmTokensUsed: 0,
    dimensionalScores: {
      D1: { score: d1Score, weight: 0.35, metrics: {} },
      D2: { score: d2Score, weight: 0.20, metrics: {} },
      D3: { score: d3Score, weight: 0.20, metrics: {} },
      D4: { score: d4Score, weight: 0.15, metrics: {} },
      D5: { score: d5Score, weight: 0.10, metrics: {} },
    },
    results,
  };
}
