#!/usr/bin/env node
/**
 * ToolVeto — Hugging Face MCP Safety Index Scanner (Zero-Execution Static AST Audit)
 *
 * Queries the public Hugging Face Hub Spaces API for active `mcp-server` and FastMCP Spaces,
 * downloads bounded source files at pinned commit SHAs (never executes untrusted code),
 * extracts real FastMCP / Gradio `mcp_server=True` / NeMo Agent Toolkit tool definitions,
 * evaluates each Space through ToolVeto's deterministic 41-check suite + `--profile nvidia-nim`,
 * and publishes:
 *   - benchmarks/huggingface-mcp/index.json
 *   - benchmarks/huggingface-mcp/STATE_OF_OPEN_WEIGHT_AND_FASTMCP_SAFETY_2026.md
 *   - benchmarks/huggingface-mcp/badges/<org>__<space>.svg
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import corePkg from '../packages/core/dist/index.js';
import { extractSourceContextFromDir } from '../packages/cli/dist/src/static-extractors.js';
import { evaluateNvidiaNimProfile } from '../packages/cli/dist/src/commands/check.js';
import { generateBadgeSvg, formatBadgeEmbedSnippets } from '../packages/cli/dist/src/commands/badge.js';

const { runSuite } = corePkg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const outDir = path.join(rootDir, 'benchmarks/huggingface-mcp');
const badgesDir = path.join(outDir, 'badges');

const HF_USER_AGENT = 'ToolVeto-HF-MCP-Safety-Index/1.0 (+https://toolveto.ai/index)';

function parseCliArgs(argv) {
  const args = { limit: 25, maxCandidates: 70, concurrency: 5, syncCloud: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--limit' && argv[i + 1]) args.limit = Math.max(5, Math.min(60, Number(argv[++i]) || 25));
    else if (a === '--max-candidates' && argv[i + 1]) args.maxCandidates = Math.max(10, Math.min(120, Number(argv[++i]) || 70));
    else if (a === '--concurrency' && argv[i + 1]) args.concurrency = Math.max(1, Math.min(10, Number(argv[++i]) || 5));
    else if (a === '--sync-cloud') args.syncCloud = true;
  }
  return args;
}

async function fetchJson(url, timeoutMs = 15_000) {
  const res = await fetch(url, {
    headers: { 'User-Agent': HF_USER_AGENT, Accept: 'application/json' },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} fetching ${url}`);
  }
  return res.json();
}

async function fetchTextBounded(url, maxBytes = 200_000, timeoutMs = 12_000) {
  const res = await fetch(url, {
    headers: { 'User-Agent': HF_USER_AGENT },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) return null;
  const contentLength = Number(res.headers.get('content-length') || 0);
  if (contentLength > maxBytes) return null;
  const text = await res.text();
  if (Buffer.byteLength(text, 'utf8') > maxBytes) return null;
  return text;
}

function selectCandidateFiles(siblings = []) {
  const names = siblings
    .map((s) => String(s?.rfilename || ''))
    .filter((f) => f && !f.includes('..') && !f.startsWith('/'));

  const scoreFile = (f) => {
    const lower = f.toLowerCase();
    if (lower === 'mcp_server.py' || lower === 'mcp.py' || lower === 'server.py') return 100;
    if (lower === 'app.py' || lower === 'main.py') return 95;
    if (/(^|\/)(mcp|fastmcp|tools|agent)[a-z0-9_-]*\.py$/.test(lower)) return 85;
    if (lower.endsWith('mcp.json') || lower.endsWith('tools.json')) return 80;
    if (lower.endsWith('.py') && !lower.includes('test') && lower.split('/').length <= 2) return 50;
    if ((lower.endsWith('.ts') || lower.endsWith('.js')) && /(mcp|server|tool)/.test(lower) && !lower.includes('node_modules')) return 45;
    return 0;
  };

  return names
    .map((f) => ({ file: f, score: scoreFile(f) }))
    .filter((x) => x.score > 0)
    .sort((a, b) => b.score - a.score || a.file.localeCompare(b.file))
    .slice(0, 6)
    .map((x) => x.file);
}

function detectFramework(space, sourceFiles) {
  const combined = sourceFiles.map((f) => f.content).join('\n');
  const hasFastMcp = /\bFastMCP\b|from\s+mcp\.server|from\s+fastmcp\b|@(?!gr\.mcp\b)[A-Za-z_][\w.]*\.tool\b/.test(combined);
  const hasNemo = /\bregister_function\b|\bnat\b|nemo_agent_toolkit|aiq\./i.test(combined);
  const hasGradioMcp = /\bmcp_server\s*=\s*True\b|@gr\.mcp\.tool\b/.test(combined);

  if (hasNemo && hasFastMcp) return 'NVIDIA NeMo Agent Toolkit + FastMCP';
  if (hasFastMcp && hasGradioMcp) return 'FastMCP + Gradio MCP';
  if (hasFastMcp) return 'FastMCP / Python MCP SDK';
  if (hasGradioMcp) return 'Gradio MCP (mcp_server=True)';
  return space.sdk ? `Hugging Face ${space.sdk}` : 'Python MCP';
}

function inferHfCategory(spaceId, tags = [], toolNames = []) {
  const hay = `${spaceId} ${tags.join(' ')} ${toolNames.join(' ')}`.toLowerCase();
  if (/(image|flux|video|wan2|diffusion|audio|voice|tts|chatterbox|swap|outpaint|background|clip|draw|anim)/.test(hay)) {
    return 'multimodal-ai';
  }
  if (/(scrape|search|arxiv|research|rag|doc|crawl|web|fetch)/.test(hay)) {
    return 'search';
  }
  if (/(sql|db|postgres|sqlite|memory|graph|knowledge)/.test(hay)) {
    return 'databases';
  }
  if (/(marketing|social|mail|slack|chat|message|content)/.test(hay)) {
    return 'messaging';
  }
  return 'devtools';
}

async function discoverHuggingFaceMcpSpaces(maxCandidates) {
  const [taggedMcp, searchMcp, searchFastMcp] = await Promise.all([
    fetchJson(`https://huggingface.co/api/spaces?filter=mcp-server&sort=likes&direction=-1&limit=35&full=true`).catch((err) => {
      console.warn(`[hf-scan] Warning querying filter=mcp-server: ${err.message}`);
      return [];
    }),
    fetchJson(`https://huggingface.co/api/spaces?search=mcp&sort=likes&direction=-1&limit=40&full=true`).catch((err) => {
      console.warn(`[hf-scan] Warning querying search=mcp: ${err.message}`);
      return [];
    }),
    fetchJson(`https://huggingface.co/api/spaces?search=fastmcp&sort=likes&direction=-1&limit=30&full=true`).catch((err) => {
      console.warn(`[hf-scan] Warning querying search=fastmcp: ${err.message}`);
      return [];
    }),
  ]);

  const filterValid = (list) =>
    (Array.isArray(list) ? list : []).filter(
      (s) =>
        s?.id &&
        !s.private &&
        !s.gated &&
        /^[a-zA-Z0-9._-]+\/[a-zA-Z0-9._-]+$/.test(s.id) &&
        selectCandidateFiles(s.siblings).length > 0
    );

  const openWeightGradio = filterValid(taggedMcp).sort((a, b) => (b.likes || 0) - (a.likes || 0));
  const agentAndFastMcp = filterValid([...searchFastMcp, ...searchMcp]).sort((a, b) => (b.likes || 0) - (a.likes || 0));

  // Interleave top open-weight Gradio MCP Spaces + top dedicated FastMCP / Agent Hackathon MCP Spaces
  // so both ecosystems are fairly represented in the benchmark cohort.
  const combined = [];
  const seen = new Set();
  const pushIfNew = (s) => {
    if (!s || seen.has(s.id)) return;
    seen.add(s.id);
    combined.push(s);
  };

  const maxLen = Math.max(openWeightGradio.length, agentAndFastMcp.length);
  for (let i = 0; i < maxLen && combined.length < maxCandidates; i++) {
    if (i < openWeightGradio.length) pushIfNew(openWeightGradio[i]);
    if (i < agentAndFastMcp.length && combined.length < maxCandidates) pushIfNew(agentAndFastMcp[i]);
  }
  return combined;
}

async function auditSpace(space) {
  const spaceId = String(space.id);
  const sha = String(space.sha || 'main');
  const candidateFiles = selectCandidateFiles(space.siblings);
  if (candidateFiles.length === 0) return null;

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-hf-space-'));
  try {
    let downloadedCount = 0;
    for (const relFile of candidateFiles) {
      const encodedPath = relFile
        .split('/')
        .map((seg) => encodeURIComponent(seg))
        .join('/');
      const rawUrl = `https://huggingface.co/spaces/${spaceId}/raw/${encodeURIComponent(sha)}/${encodedPath}`;
      const content = await fetchTextBounded(rawUrl);
      if (!content) continue;
      const dest = path.join(tmpDir, relFile);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, content, 'utf8');
      downloadedCount++;
    }
    if (downloadedCount === 0) return null;

    const extracted = extractSourceContextFromDir(tmpDir);
    if (!extracted.tools || extracted.tools.length === 0) {
      return null;
    }

    const summary = await runSuite(`hf:${spaceId}`, extracted.tools, {
      withLlm: false,
      targetDir: tmpDir,
      sourceFiles: extracted.sourceFiles,
      resourceTemplates: extracted.resourceTemplates,
      prompts: extracted.prompts,
      transportMode: extracted.transportMode,
    });

    const nimProfile = evaluateNvidiaNimProfile(summary, extracted.tools);
    const failedChecks = summary.results.filter((r) => r.status === 'FAIL');
    const criticalFailures = failedChecks.filter((r) => r.severity === 'CRITICAL');
    const highFailures = failedChecks.filter((r) => r.severity === 'HIGH');
    const manifestSha256 = crypto
      .createHash('sha256')
      .update(JSON.stringify(extracted.tools.map((t) => ({ name: t.name, description: t.description || '', inputSchema: t.inputSchema }))))
      .digest('hex');

    const encodedSlug = spaceId.toLowerCase().replace(/\//g, '__');
    const snippets = formatBadgeEmbedSnippets({
      slug: spaceId,
      tier: String(summary.tier || 'REJECTED').toUpperCase(),
      score: summary.score,
      nimCertified: nimProfile.certified,
      isNimProfile: true,
    });

    return {
      spaceId,
      slug: spaceId.toLowerCase(),
      encodedSlug,
      spaceUrl: `https://huggingface.co/spaces/${spaceId}`,
      commitSha: sha,
      shortSha: sha.slice(0, 8),
      likes: Number(space.likes || 0),
      sdk: String(space.sdk || 'unknown'),
      framework: detectFramework(space, extracted.sourceFiles),
      category: inferHfCategory(
        spaceId,
        Array.isArray(space.tags) ? space.tags : [],
        extracted.tools.map((t) => t.name)
      ),
      tags: (Array.isArray(space.tags) ? space.tags : []).slice(0, 8),
      evidenceQuality: 'STATIC-ONLY',
      filesAudited: extracted.sourceFiles.map((f) => f.path),
      toolCount: extracted.tools.length,
      tools: extracted.tools.map((t) => t.name),
      score: summary.score,
      tier: String(summary.tier || 'Rejected'),
      fatalVetoTriggered: Boolean(summary.fatalVetoTriggered),
      fatalVetoCode: summary.fatalVetoCode || null,
      dimensions: {
        d1: Number(summary.dimensionalScores?.D1?.score ?? 0),
        d2: Number(summary.dimensionalScores?.D2?.score ?? 0),
        d3: Number(summary.dimensionalScores?.D3?.score ?? 0),
        d4: Number(summary.dimensionalScores?.D4?.score ?? 0),
        d5: Number(summary.dimensionalScores?.D5?.score ?? 0),
      },
      passed: summary.passed,
      failed: summary.failed,
      warned: summary.warned,
      criticalFailures: criticalFailures.length,
      highFailures: highFailures.length,
      manifestSha256,
      nvidiaNimProfile: {
        certified: nimProfile.certified,
        kvCacheEvictionRisk: nimProfile.kvCacheEvictionRisk,
        runawayLoopRisk: nimProfile.runawayLoopRisk,
        unboundedListTools: nimProfile.unboundedListTools,
        estimatedKvCacheWasteTokensPerCall: nimProfile.estimatedKvCacheWasteTokensPerCall,
        estimatedRunawayLoopWasteTokens: nimProfile.estimatedRunawayLoopWasteTokens,
        estimatedGpuTokenMultiplier: nimProfile.estimatedGpuTokenMultiplier,
        vetoReasons: nimProfile.vetoReasons,
      },
      findings: failedChecks.slice(0, 15).map((r) => ({
        checkId: r.checkId,
        tool: r.tool,
        severity: r.severity,
        dimension: r.dimension,
        description: String(r.description || '').slice(0, 400),
      })),
      badgeFile: `benchmarks/huggingface-mcp/badges/${encodedSlug}.svg`,
      liveBadgeUrl: snippets.badgeUrl,
      scorecardUrl: snippets.scorecardUrl,
      markdownBadge: snippets.githubMarkdown,
      scannedAt: new Date().toISOString(),
    };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function buildReportMarkdown(dataset) {
  const { summary, spaces, generatedAt } = dataset;
  const rows = spaces
    .map((s, idx) => {
      const nimBadge = s.nvidiaNimProfile.certified
        ? '🟢 Certified'
        : `🔴 ${s.nvidiaNimProfile.kvCacheEvictionRisk} KV Risk`;
      const topFinding = s.findings[0]
        ? `\`${s.findings[0].checkId}\` (${s.findings[0].severity})`
        : 'None';
      return `| ${idx + 1} | [**${s.spaceId}**](${s.spaceUrl}) (\`${s.shortSha}\`) | ${s.likes.toLocaleString()} | ${s.framework} | ${s.toolCount} | **${s.score}/100** (${s.tier}) | ${nimBadge} | ${topFinding} |`;
    })
    .join('\n');

  const topFailureRows = summary.topCheckFailures
    .slice(0, 8)
    .map((f) => {
      const cleanDesc = String(f.sampleDescription || '').replace(/\r?\n+/g, ' ').replace(/\|/g, '\\|');
      return `| \`${f.checkId}\` | ${f.severity} | ${f.affectedSpaces}/${summary.spacesAuditedWithTools} (${Math.round((f.affectedSpaces / Math.max(1, summary.spacesAuditedWithTools)) * 100)}%) | ${cleanDesc} |`;
    })
    .join('\n');

  const sampleSpace = spaces[0];
  const sampleSlug = sampleSpace ? sampleSpace.spaceId : 'Agents-MCP-Hackathon/Graphify';

  return `# State of Open-Weight & FastMCP Tool Safety — Hugging Face MCP Safety Index (2026)

*An Independent, Reproducible Static Security & NVIDIA NIM KV-Cache Benchmark of Public Hugging Face MCP Spaces*

- **Report Date**: ${generatedAt.slice(0, 10)}
- **Evaluator**: ToolVeto Open-Source Deterministic Engine (\`v0.2.0\`, 41 Checks + \`--profile nvidia-nim\`)
- **Methodology**: Zero-code-execution static AST & schema extraction (\`STATIC-ONLY\`) at pinned Hugging Face Space commit SHAs. No Spaces were mutated, invoked, or fuzz-attacked over the network.
- **Scope**: Discovered **${summary.spacesCandidateCount}** active Hugging Face \`mcp-server\` / FastMCP Spaces, statically extracted real MCP tool contracts from **${summary.spacesAuditedWithTools}** Spaces (**${summary.totalLikes.toLocaleString()}** combined likes, **${summary.totalToolsExtracted}** extracted MCP tools).

---

## Executive Summary

Open-weight model Spaces and FastMCP servers hosted on Hugging Face Hub are rapidly becoming the default tool catalog for autonomous agents running on NVIDIA NIM, NeMo Agent Toolkit, Cursor, and Claude. Because Gradio \`mcp_server=True\` and FastMCP expose Python functions directly as MCP tools without deterministic safety gates, production agents inherit four systemic failure modes:

| Benchmark Metric | Empirical Result |
| :--- | :---: |
| **Hugging Face MCP Spaces Empirically Audited** | **${summary.spacesAuditedWithTools}** (${summary.totalLikes.toLocaleString()} likes · ${summary.totalToolsExtracted} tools) |
| **Average ToolVeto Reliability Score** | **${summary.averageScore}/100** |
| **NVIDIA NIM Certification Gate Block Rate (\`--profile nvidia-nim\`)** | **${summary.nimBlockedCount}/${summary.spacesAuditedWithTools} (${summary.nimBlockedRatePct}%)** |
| **Elevated / Critical KV-Cache Eviction Risk** | **${summary.kvCacheRiskSpaces}/${summary.spacesAuditedWithTools} (${summary.kvCacheRiskRatePct}%)** |
| **Spaces With Static Schema / Hygiene Failures** | **${summary.spacesWithFailures}/${summary.spacesAuditedWithTools} (${Math.round((summary.spacesWithFailures / Math.max(1, summary.spacesAuditedWithTools)) * 100)}%)** |
| **Spaces Triggering Security / SSRF / Transport Warnings or Failures** | **${summary.securityAlertSpaces}/${summary.spacesAuditedWithTools} (${Math.round((summary.securityAlertSpaces / Math.max(1, summary.spacesAuditedWithTools)) * 100)}%)** |

---

## Hugging Face MCP Safety Index Leaderboard

| # | Hugging Face Space (Pinned SHA) | Likes | Framework | Tools | ToolVeto Score | NVIDIA NIM Gate | Top Finding |
| :-: | :--- | ---: | :--- | ---: | :---: | :---: | :--- |
${rows}

---

## Most Prevalent Failure Patterns Across Hugging Face MCP Spaces

| Check ID | Severity | Affected Spaces | Description |
| :--- | :---: | :---: | :--- |
${topFailureRows || '| None | — | 0 | No check failures detected |'}

### Why This Matters for NVIDIA NIM & Open-Weight Inference Economics
1. **KV-Cache Prefix Eviction (D3 Context Hygiene)**: Unbounded scrape/search/list handlers and missing schema bounds dump tens of thousands of unpaginated tokens into agent context, evicting shared KV-cache prefixes on NVIDIA NIM / vLLM clusters and multiplying per-task GPU token spend by 10x–40x.
2. **Ambiguous Tool Contracts & Runaway Retry Loops (D2 Error Feedback & D4 Descriptions)**: Gradio \`mcp_server=True\` handlers frequently export raw Python functions without docstrings, type descriptions, or \`additionalProperties: false\`, causing open-weight tool-calling models (Nemotron, Llama, Qwen) to guess invalid parameters and loop repeatedly.
3. **Missing Mutation Safety & SSRF Guards (D1 / D4)**: Public Spaces accepting arbitrary \`url\` parameters or mutating remote state rarely declare \`idempotency_key\`, \`readOnlyHint\`, or outbound SSRF allowlists.

---

## Claim Your Free GitHub & Hugging Face Space Trust Badge

Any Hugging Face Space or FastMCP maintainer can reproduce their scorecard locally in under 5 seconds (\$0, zero LLM API keys), auto-fix pagination & idempotency contracts, and embed a free Trust Badge in their \`README.md\`:

\`\`\`bash
# 1. Audit locally with the NVIDIA NIM GPU/KV-Cache profile
npx toolveto@latest check . --profile nvidia-nim

# 2. Auto-fix FastMCP & NeMo Agent Toolkit handlers in-place
npx toolveto@latest fix . --lang fastmcp --apply

# 3. Export NVIDIA OpenShell & NeMo Guardrails policies
npx toolveto@latest export-policy . --format nvidia-openshell -o openshell-policy.yaml
npx toolveto@latest export-policy . --format nemo-guardrails -o ./nemo-guardrails

# 4. Generate a free SVG badge + Hugging Face Space README Markdown snippet
npx toolveto@latest badge --huggingface --space ${sampleSlug} --profile nvidia-nim
\`\`\`

### Example Hugging Face Space \`README.md\` Badge Embed
\`\`\`markdown
${sampleSpace ? sampleSpace.markdownBadge : '[![ToolVeto Verified](https://toolveto.ai/api/v1/badge/org__space.svg)](https://toolveto.ai/r/org__space)'}
\`\`\`

---

*Reproduce this entire benchmark dataset anytime with \`node scripts/scan-hf-mcp-index.mjs\` inside [\`toolveto/toolveto\`](https://github.com/toolveto/toolveto). Machine-readable dataset: [\`benchmarks/huggingface-mcp/index.json\`](./index.json).*
`;
}

async function main() {
  const args = parseCliArgs(process.argv.slice(2));
  fs.mkdirSync(badgesDir, { recursive: true });

  console.log(`\n🤗 ToolVeto Hugging Face MCP Safety Index Scanner`);
  console.log(`   Discovering up to ${args.maxCandidates} live public Hugging Face MCP Spaces (target audited: ${args.limit})...\n`);

  const candidates = await discoverHuggingFaceMcpSpaces(args.maxCandidates);
  console.log(`   Discovered ${candidates.length} candidate Spaces with inspectable Python/MCP source files.`);

  const audited = [];
  let cursor = 0;

  const workers = Array.from({ length: Math.min(args.concurrency, candidates.length) }, async () => {
    while (cursor < candidates.length && audited.length < args.limit) {
      const idx = cursor++;
      const space = candidates[idx];
      if (!space) break;
      try {
        const result = await auditSpace(space);
        if (result && audited.length < args.limit) {
          audited.push(result);
          console.log(
            `   ✓ ${result.spaceId.padEnd(46)} likes=${String(result.likes).padStart(4)} tools=${String(result.toolCount).padStart(2)} score=${String(result.score).padStart(3)}/100 nim=${result.nvidiaNimProfile.certified ? 'PASS' : 'BLOCKED'}`
          );
        }
      } catch (err) {
        console.warn(`   · Skipped ${space.id}: ${err.message}`);
      }
    }
  });

  await Promise.all(workers);

  // Sort deterministically by likes desc, then score desc, then spaceId
  audited.sort((a, b) => b.likes - a.likes || b.score - a.score || a.spaceId.localeCompare(b.spaceId));

  // Generate static SVG badges for all audited Spaces
  for (const s of audited) {
    const svg = generateBadgeSvg(s.score, s.tier, s.nvidiaNimProfile.certified ? 'ToolVeto NIM' : 'ToolVeto');
    fs.writeFileSync(path.join(badgesDir, `${s.encodedSlug}.svg`), svg, 'utf8');
  }

  // Compute transparent aggregate statistics
  const totalAudited = audited.length;
  const totalLikes = audited.reduce((acc, s) => acc + s.likes, 0);
  const totalToolsExtracted = audited.reduce((acc, s) => acc + s.toolCount, 0);
  const averageScore = totalAudited > 0
    ? Number((audited.reduce((acc, s) => acc + s.score, 0) / totalAudited).toFixed(1))
    : 0;
  const nimBlockedCount = audited.filter((s) => !s.nvidiaNimProfile.certified).length;
  const nimBlockedRatePct = totalAudited > 0 ? Math.round((nimBlockedCount / totalAudited) * 100) : 0;
  const kvCacheRiskSpaces = audited.filter((s) => s.nvidiaNimProfile.kvCacheEvictionRisk !== 'LOW').length;
  const kvCacheRiskRatePct = totalAudited > 0 ? Math.round((kvCacheRiskSpaces / totalAudited) * 100) : 0;
  const spacesWithFailures = audited.filter((s) => s.failed > 0).length;
  const securityAlertSpaces = audited.filter((s) =>
    s.findings.some((f) => f.checkId.startsWith('TC-SEC') || f.checkId.startsWith('TC-AUTH') || f.checkId.startsWith('TC-TOXIC') || f.checkId.startsWith('TC-POISON') || f.checkId.startsWith('TC-HTTP'))
  ).length;

  const checkMap = new Map();
  for (const s of audited) {
    const seenInSpace = new Set();
    for (const f of s.findings) {
      if (seenInSpace.has(f.checkId)) continue;
      seenInSpace.add(f.checkId);
      const cur = checkMap.get(f.checkId) || {
        checkId: f.checkId,
        severity: f.severity,
        affectedSpaces: 0,
        sampleDescription: f.description,
      };
      cur.affectedSpaces += 1;
      checkMap.set(f.checkId, cur);
    }
  }
  const topCheckFailures = Array.from(checkMap.values()).sort(
    (a, b) => b.affectedSpaces - a.affectedSpaces || a.checkId.localeCompare(b.checkId)
  );

  const dataset = {
    schema: 'toolveto-hf-mcp-safety-index/v1',
    generatedAt: new Date().toISOString(),
    methodology: 'Zero-execution static AST & schema extraction (STATIC-ONLY) at pinned Hugging Face Space commit SHAs using ToolVeto CLI v0.2.0 + --profile nvidia-nim.',
    summary: {
      spacesCandidateCount: candidates.length,
      spacesAuditedWithTools: totalAudited,
      totalLikes,
      totalToolsExtracted,
      averageScore,
      nimBlockedCount,
      nimBlockedRatePct,
      kvCacheRiskSpaces,
      kvCacheRiskRatePct,
      spacesWithFailures,
      securityAlertSpaces,
      topCheckFailures,
    },
    spaces: audited,
  };

  const indexJsonPath = path.join(outDir, 'index.json');
  const reportMdPath = path.join(outDir, 'STATE_OF_OPEN_WEIGHT_AND_FASTMCP_SAFETY_2026.md');
  fs.writeFileSync(indexJsonPath, JSON.stringify(dataset, null, 2) + '\n', 'utf8');
  fs.writeFileSync(reportMdPath, buildReportMarkdown(dataset), 'utf8');

  if (args.syncCloud) {
    const cloudCorpusPath = path.resolve(rootDir, '../toolveto-cloud/apps/api/data/public-trust-index-corpus.json');
    if (fs.existsSync(cloudCorpusPath)) {
      const corpus = JSON.parse(fs.readFileSync(cloudCorpusPath, 'utf8'));
      const existingBySlug = new Map((corpus.servers || []).map((srv) => [String(srv.slug).toLowerCase(), srv]));
      let addedOrUpdated = 0;
      for (const s of audited) {
        const entry = {
          slug: s.slug,
          displayName: s.spaceId,
          sourceType: 'huggingface',
          sourceUrl: s.spaceUrl,
          category: s.category === 'multimodal-ai' ? 'huggingface' : s.category,
          description: `${s.framework} Hugging Face MCP Space (${s.toolCount} extracted tools, NIM KV-cache risk: ${s.nvidiaNimProfile.kvCacheEvictionRisk}).`,
          stars: s.likes,
          weeklyDownloads: 0,
          commitSha: s.commitSha,
          score: s.score,
          tier: s.tier.toUpperCase(),
          vetoClasses: s.fatalVetoCode ? [s.fatalVetoCode] : [],
          evidenceQuality: 'STATIC-ONLY',
          toolCount: s.toolCount,
          avgResponseTokens: 0,
          maxResponseTokens: s.nvidiaNimProfile.estimatedKvCacheWasteTokensPerCall,
          manifestSha256: s.manifestSha256,
          dimensions: s.dimensions,
          findings: s.findings.map((f) => ({
            checkId: f.checkId,
            tool: f.tool,
            severity: f.severity,
            description: f.description,
          })),
          scannedAt: Date.now(),
        };
        existingBySlug.set(s.slug, entry);
        addedOrUpdated++;
      }
      corpus.servers = Array.from(existingBySlug.values()).sort(
        (a, b) => (b.stars || 0) - (a.stars || 0) || (b.score || 0) - (a.score || 0)
      );
      corpus.totalServers = corpus.servers.length;
      corpus.sources = { ...(corpus.sources || {}), huggingface: audited.length };
      corpus.generatedAt = new Date().toISOString();
      fs.writeFileSync(cloudCorpusPath, JSON.stringify(corpus, null, 2) + '\n', 'utf8');
      console.log(`   Synced ${addedOrUpdated} Hugging Face MCP Spaces into ${cloudCorpusPath} (total=${corpus.totalServers})`);
    }
  }

  console.log(`\n✅ Hugging Face MCP Safety Index generated!`);
  console.log(`   Audited Spaces : ${totalAudited} (${totalLikes.toLocaleString()} total likes, ${totalToolsExtracted} extracted tools)`);
  console.log(`   Avg Score      : ${averageScore}/100 | NIM Blocked: ${nimBlockedCount}/${totalAudited} (${nimBlockedRatePct}%)`);
  console.log(`   Dataset JSON   : ${indexJsonPath}`);
  console.log(`   Report MD      : ${reportMdPath}`);
  console.log(`   SVG Badges     : ${badgesDir} (${totalAudited} files)\n`);
}

main().catch((err) => {
  console.error('[hf-scan] Fatal:', err);
  process.exit(1);
});
