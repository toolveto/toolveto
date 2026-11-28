import fs from 'fs';
import path from 'path';

export interface BadgeOptions {
  score?: string | number;
  tier?: string;
  output?: string;
  label?: string;
  huggingface?: boolean;
  space?: string;
  repo?: string;
  profile?: string;
  nim?: boolean;
  baseUrl?: string;
}

export interface BadgeEmbedSnippets {
  slug: string;
  encodedSlug: string;
  badgeUrl: string;
  scorecardUrl: string;
  githubMarkdown: string;
  huggingfaceMarkdown: string;
  huggingfaceYamlTags: string[];
  localSvgMarkdown: string;
}

function escapeXml(unsafe: string): string {
  return String(unsafe).replace(/[<>&'"]/g, (c) => {
    switch (c) {
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '&': return '&amp;';
      case '\'': return '&apos;';
      case '"': return '&quot;';
      default: return c;
    }
  });
}

export function normalizeTargetSlug(raw?: string): string | undefined {
  if (!raw) return undefined;
  const cleaned = String(raw)
    .trim()
    .replace(/^https?:\/\/(?:www\.)?huggingface\.co\/spaces\//i, '')
    .replace(/^https?:\/\/(?:www\.)?github\.com\//i, '')
    .replace(/\.git$/i, '')
    .replace(/^\/+|\/+$/g, '')
    .replace(/__/g, '/');
  const parts = cleaned.split('/').filter(Boolean);
  if (parts.length < 2) return undefined;
  const candidate = `${parts[0]}/${parts[1]}`;
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}\/[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$/.test(candidate)) {
    return undefined;
  }
  return candidate;
}

export function formatBadgeEmbedSnippets(params: {
  slug: string;
  tier: string;
  score: number;
  nimCertified?: boolean;
  isNimProfile?: boolean;
  outputFile?: string;
  baseUrl?: string;
}): BadgeEmbedSnippets {
  const baseUrl = (params.baseUrl || 'https://toolveto.ai').replace(/\/+$/, '');
  const encodedSlug = params.slug.toLowerCase().replace(/\//g, '__');
  const query = params.isNimProfile ? '?label=ToolVeto+NIM' : '';
  const badgeUrl = `${baseUrl}/api/v1/badge/${encodeURIComponent(encodedSlug)}.svg${query}`;
  const scorecardUrl = `${baseUrl}/r/${encodeURIComponent(encodedSlug)}`;
  const altText = params.isNimProfile
    ? `ToolVeto NVIDIA NIM ${params.nimCertified ? 'Certified' : 'Checked'} (${params.score}/100)`
    : `ToolVeto ${params.tier} ${params.score}/100`;
  const githubMarkdown = `[![${altText}](${badgeUrl})](${scorecardUrl})`;
  const huggingfaceMarkdown = [
    `[![${altText}](${badgeUrl})](${scorecardUrl})`,
    `<!-- Paste at the top of your Hugging Face Space README.md (below the YAML frontmatter) -->`,
  ].join('\n');
  const localFile = params.outputFile ? `./${path.basename(params.outputFile)}` : './toolveto-badge.svg';
  const huggingfaceYamlTags = ['mcp-server', 'toolveto-verified'];
  if (params.isNimProfile && params.nimCertified) {
    huggingfaceYamlTags.push('nvidia-nim-ready');
  }
  return {
    slug: params.slug,
    encodedSlug,
    badgeUrl,
    scorecardUrl,
    githubMarkdown,
    huggingfaceMarkdown,
    huggingfaceYamlTags,
    localSvgMarkdown: `[![${altText}](${localFile})](${scorecardUrl})`,
  };
}

export function generateBadgeSvg(score: number, tier: string, rawLabel = 'ToolVeto'): string {
  const safeScore = Math.max(0, Math.min(100, Math.round(Number(score) || 0)));
  const normalizedTier = ['PLATINUM', 'GOLD', 'SILVER', 'BRONZE', 'REJECTED', 'UNVERIFIED'].includes(tier.toUpperCase())
    ? tier.toUpperCase()
    : 'REJECTED';

  let color = '#ff4757'; // Red for Rejected
  if (normalizedTier === 'PLATINUM') color = '#2ed573';
  else if (normalizedTier === 'GOLD') color = '#ffa502';
  else if (normalizedTier === 'SILVER') color = '#70a1ff';
  else if (normalizedTier === 'BRONZE') color = '#eccc68';
  else if (normalizedTier === 'UNVERIFIED') color = '#747d8c';

  const safeRawLabel = String(rawLabel || 'ToolVeto').slice(0, 32);
  const label = escapeXml(safeRawLabel);
  const status = escapeXml(`${normalizedTier} ${safeScore}/100`);
  const leftWidth = safeRawLabel === 'ToolVeto' ? 65 : Math.max(65, Math.round(safeRawLabel.length * 6.8) + 14);
  const rightWidth = 95;
  const totalWidth = leftWidth + rightWidth;
  const leftTextX = Math.round((leftWidth / 2) * 10);
  const leftTextLen = Math.round((leftWidth - 10) * 10);
  const rightTextX = Math.round((leftWidth + rightWidth / 2) * 10);
  const rightTextLen = Math.round((rightWidth - 10) * 10);

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20" role="img" aria-label="${label}: ${status}">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="${totalWidth}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="${leftWidth}" height="20" fill="#1e1e24"/>
    <rect x="${leftWidth}" width="${rightWidth}" height="20" fill="${color}"/>
    <rect width="${totalWidth}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="${leftTextX}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${leftTextLen}">${label}</text>
    <text x="${leftTextX}" y="140" transform="scale(.1)" fill="#fff" textLength="${leftTextLen}">${label}</text>
    <text aria-hidden="true" x="${rightTextX}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${rightTextLen}">${status}</text>
    <text x="${rightTextX}" y="140" transform="scale(.1)" fill="#fff" textLength="${rightTextLen}">${status}</text>
  </g>
</svg>`;
}

export async function badgeCommand(options: BadgeOptions = {}): Promise<BadgeEmbedSnippets | undefined> {
  let hydratedScore: number | undefined =
    options.score !== undefined ? Math.max(0, Math.min(100, Math.round(Number(options.score) || 0))) : undefined;
  let hydratedTier: string | undefined = options.tier ? options.tier.toUpperCase() : undefined;
  let hydratedNimCertified: boolean | undefined;

  if (hydratedScore === undefined || hydratedTier === undefined || hydratedNimCertified === undefined) {
    const reportPath = path.resolve(process.cwd(), 'toolveto-report.json');
    if (fs.existsSync(reportPath)) {
      try {
        const parsed = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
        if (hydratedScore === undefined && typeof parsed?.score === 'number') {
          hydratedScore = Math.max(0, Math.min(100, Math.round(parsed.score)));
        }
        if (hydratedTier === undefined && typeof parsed?.tier === 'string' && parsed.tier.trim()) {
          hydratedTier = parsed.tier.trim().toUpperCase();
        }
        if (typeof parsed?.nvidiaNimProfile?.certified === 'boolean') {
          hydratedNimCertified = parsed.nvidiaNimProfile.certified;
        }
      } catch {
        // Ignore invalid report JSON
      }
    }
  }

  const normalizedProfile = (options.profile || '').trim().toLowerCase();
  const isNimProfile = Boolean(options.nim || normalizedProfile === 'nvidia-nim' || normalizedProfile === 'nim');
  const hasScore = hydratedScore !== undefined;
  const score = hydratedScore ?? 0;
  const tier = hydratedTier
    ? hydratedTier
    : hasScore
    ? score >= 90 ? 'PLATINUM' : score >= 80 ? 'GOLD' : score >= 70 ? 'SILVER' : 'REJECTED'
    : 'UNVERIFIED';
  const outputPath = options.output
    ? path.resolve(process.cwd(), options.output)
    : path.resolve(process.cwd(), 'toolveto-badge.svg');

  const label = options.label || (isNimProfile ? 'ToolVeto NIM' : 'ToolVeto');
  const svg = generateBadgeSvg(score, tier, label);
  fs.writeFileSync(outputPath, svg, 'utf8');

  console.log(`\n🛡️ ToolVeto Badge Generated!`);
  console.log(`Label:  ${label}`);
  console.log(`Tier:   ${tier}`);
  console.log(`Score:  ${score}/100`);
  console.log(`Output: ${outputPath}`);

  const resolvedSlug = normalizeTargetSlug(options.space || options.repo);
  if (options.huggingface || resolvedSlug) {
    const effectiveSlug = resolvedSlug || 'your-org/your-mcp-space';
    const snippets = formatBadgeEmbedSnippets({
      slug: effectiveSlug,
      tier,
      score,
      nimCertified: hydratedNimCertified ?? (tier === 'PLATINUM' || tier === 'GOLD'),
      isNimProfile,
      outputFile: outputPath,
      baseUrl: options.baseUrl,
    });
    console.log(`\n📦 GitHub README Trust Badge (Live):`);
    console.log(`  ${snippets.githubMarkdown}`);
    if (options.huggingface || options.space) {
      console.log(`\n🤗 Hugging Face Space README.md Trust Badge:`);
      console.log(`  ${snippets.githubMarkdown}`);
      console.log(`  # Suggested Space YAML tags: [${snippets.huggingfaceYamlTags.join(', ')}]`);
    }
    console.log('');
    return snippets;
  }

  console.log('');
  return undefined;
}
