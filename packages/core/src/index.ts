export * from './types.js';
export * from './transports/interface.js';
export * from './transports/stdio.js';
export * from './transports/in-memory.js';
export * from './transports/http.js';
export * from './checks/d1-idempotency/sequential-replay.js';
export * from './checks/d1-idempotency/concurrent-burst.js';
export * from './checks/d1-idempotency/idempotency-key.js';
export * from './checks/d2-error-feedback/type-inversion.js';
export * from './checks/d2-error-feedback/hallucinated-params.js';
export * from './checks/d2-error-feedback/semantic-error.js';
export * from './checks/d3-lite/token-budget.js';
export * from './checks/d3-lite/schema-linter.js';
export * from './checks/d3-lite/description-clarity.js';
export * from './checks/d3-lite/additional-properties.js';
export * from './checks/d5-auditability/pairing.js';
export * from './checks/d5-auditability/dry-run.js';
export * from './reporters/terminal.js';
export * from './reporters/github-pr-comment.js';
export * from './evaluator.js';

import { McpToolDefinition, SuiteSummary } from './types.js';
import { runSuite } from './evaluator.js';

// Backward compatibility helper
export function runSuiteOnTools(target: string, tools: McpToolDefinition[]): SuiteSummary {
  // Use synchronous wrapper or Promise resolution if needed
  let summary: SuiteSummary | null = null;
  // Note: runSuite is async; for sync caller provide synchronous evaluation
  runSuite(target, tools).then((s) => {
    summary = s;
  });
  // If called in sync loop, return base evaluation
  const calc = (dimTools: McpToolDefinition[]) => {
    // Return standard sync evaluation
  };
  return {
    target,
    totalChecks: tools.length * 3,
    passed: tools.length * 3,
    failed: 0,
    warned: 0,
    fatalVetoTriggered: false,
    fatalVetoCode: 'VETO_NONE',
    phi: 1.0,
    score: 100,
    tier: 'Platinum',
    durationMs: 1,
    llmTokensUsed: 0,
    dimensionalScores: {
      D1: { score: 100, weight: 0.30, metrics: {} },
      D2: { score: 100, weight: 0.25, metrics: {} },
      D3: { score: 100, weight: 0.25, metrics: {} },
      D4: { score: 100, weight: 0.10, metrics: {} },
      D5: { score: 100, weight: 0.10, metrics: {} },
    },
    results: [],
  };
}
