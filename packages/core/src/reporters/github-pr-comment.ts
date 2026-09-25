import { SuiteSummary } from '../types.js';

export function renderPRComment(summary: SuiteSummary): string {
  const failed = summary.results.filter((c) => c.status === 'FAIL');
  const hasCrit = failed.some((c) => c.severity === 'CRITICAL');

  const rows = summary.results
    .map(
      (c) =>
        `| ${c.status === 'PASS' ? '✅' : c.severity === 'CRITICAL' ? '🔴' : '⚠️'} ${c.dimension} | \`${c.tool}\` | ${c.checkId} | ${c.status} |`
    )
    .join('\n');

  const failDetails = failed
    .map((c) => {
      const diffBlock = c.fix?.diffs[0]?.code
        ? `\`\`\`${c.fix.diffs[0].language === 'typescript-zod' ? 'typescript' : 'python'}\n${c.fix.diffs[0].code}\n\`\`\``
        : '';
      return (
        `### ${c.severity === 'CRITICAL' ? '🔴' : '⚠️'} ${c.checkId} — \`${c.tool}\`\n` +
        `${c.description}\n\n` +
        (diffBlock ? `${diffBlock}\n\n` : '') +
        (c.fix ? `**Apply:** \`${c.fix.applyCommand || 'toolveto fix --apply'}\`` : '')
      );
    })
    .join('\n\n---\n\n');

  return `## ToolVeto Check — ${hasCrit ? '🔴 ' + failed.length + ' issue(s) found' : '✅ All checks passed'}

**Score:** ${summary.score}/100 [Tier: ${summary.tier}] · **Checks:** ${summary.passed} passed, ${summary.failed} failed

| Dimension | Tool | Check | Status |
|:----------|:-----|:------|:-------|
${rows}

${failed.length > 0 ? `\n## Remediation Diffs\n\n${failDetails}\n` : ''}

<details>
<summary>Run details (${summary.durationMs}ms · $0.00)</summary>

\`\`\`
Target: ${summary.target}
Checks evaluated: ${summary.totalChecks}
Phi multiplier: ${summary.phi}
Fatal veto code: ${summary.fatalVetoCode}
\`\`\`
</details>

${
  hasCrit || summary.fatalVetoTriggered
    ? '> ⛔ **This PR is blocked**: CRITICAL failures must be resolved before merge. Run `npx toolveto fix --apply`'
    : '> ✅ **Merge ready**: all ToolVeto resilience checks pass.'
}`;
}
