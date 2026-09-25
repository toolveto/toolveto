import { SuiteSummary } from '../types.js';

export function formatTerminalReport(summary: SuiteSummary): string {
  const lines: string[] = [];
  lines.push('');
  lines.push('================================================================================');
  lines.push(` 🛡️  TOOLVETO MCP CRASH LAB CHECK: ${summary.target}`);
  lines.push('================================================================================');
  lines.push('');

  const failedChecks = summary.results.filter((r) => r.status === 'FAIL');
  const warnedChecks = summary.results.filter((r) => r.status === 'WARN');
  const passedChecks = summary.results.filter((r) => r.status === 'PASS');

  // Print failures first
  if (failedChecks.length > 0) {
    lines.push('── FAILURES ────────────────────────────────────────────────────────────────────');
    for (const res of failedChecks) {
      const icon = res.severity === 'CRITICAL' ? '🔴' : '⚠️';
      lines.push(`${icon} [${res.dimension}] ${res.severity} FAIL — ${res.tool} (${res.checkId})`);
      lines.push(`   ${res.description}`);

      if (res.evidence.details) {
        lines.push(`   Details: ${JSON.stringify(res.evidence.details)}`);
      }

      if (res.fix) {
        lines.push('');
        lines.push(`   🔧 Fix: ${res.fix.summary}`);
        for (const diff of res.fix.diffs) {
          lines.push(`   [${diff.language}]`);
          const indentedDiff = diff.code
            .split('\n')
            .map((l) => `     ${l}`)
            .join('\n');
          lines.push(indentedDiff);
        }
        lines.push('');
        lines.push(`   [📋 Copy] [Run: ${res.fix.applyCommand || 'toolveto fix --apply'}]`);
      }
      lines.push('');
    }
  }

  // Print warnings
  if (warnedChecks.length > 0) {
    lines.push('── WARNINGS ────────────────────────────────────────────────────────────────────');
    for (const res of warnedChecks) {
      lines.push(`⚠️  [${res.dimension}] WARN — ${res.tool} (${res.checkId}): ${res.description}`);
    }
    lines.push('');
  }

  // Summary section
  lines.push('── DIMENSIONAL SCORES ──────────────────────────────────────────────────────────');
  if (summary.dimensionalScores) {
    for (const [dim, s] of Object.entries(summary.dimensionalScores)) {
      lines.push(`   ${dim}: ${s.score}% (weight ${(s.weight * 100).toFixed(0)}%)`);
    }
  }

  lines.push('');
  lines.push('--------------------------------------------------------------------------------');
  lines.push(
    `Checks: ${summary.passed} passed · ${summary.failed} failed · ${summary.warned} warnings · 0 LLM calls · $0.00 · ${(summary.durationMs / 1000).toFixed(2)}s`
  );
  lines.push(
    `ToolVeto Score: ${summary.score}/100 [Tier: ${summary.tier}] · Phi Multiplier: ${summary.phi}`
  );

  if (summary.fatalVetoTriggered) {
    lines.push('');
    lines.push('********************************************************************************');
    lines.push(`⛔ MERGE BLOCKED: FATAL VETO TRIGGERED [${summary.fatalVetoCode || 'CRITICAL_FAILURE'}]`);
    lines.push('   Auto-remediation available. Run: npx toolveto fix --apply');
    lines.push('********************************************************************************');
  } else {
    lines.push('');
    lines.push('✅ MERGE READY: All ToolVeto safety gates and invariant checks passed.');
  }

  lines.push('================================================================================');
  lines.push('');

  return lines.join('\n');
}
