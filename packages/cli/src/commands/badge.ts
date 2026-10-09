import fs from 'fs';
import path from 'path';

export interface BadgeOptions {
  score?: string | number;
  tier?: string;
  output?: string;
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

  const label = escapeXml(rawLabel);
  const status = escapeXml(`${normalizedTier} ${safeScore}/100`);

  return `<svg xmlns="http://www.w3.org/2000/svg" width="160" height="20" role="img" aria-label="${label}: ${status}">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="160" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="65" height="20" fill="#1e1e24"/>
    <rect x="65" width="95" height="20" fill="${color}"/>
    <rect width="160" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="335" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="550">${label}</text>
    <text x="335" y="140" transform="scale(.1)" fill="#fff" textLength="550">${label}</text>
    <text aria-hidden="true" x="1115" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="850">${status}</text>
    <text x="1115" y="140" transform="scale(.1)" fill="#fff" textLength="850">${status}</text>
  </g>
</svg>`;
}

export async function badgeCommand(options: BadgeOptions = {}): Promise<void> {
  const score = Math.max(0, Math.min(100, Math.round(Number(options.score) || 100)));
  const tier = (options.tier || (score >= 90 ? 'PLATINUM' : score >= 80 ? 'GOLD' : score >= 70 ? 'SILVER' : 'REJECTED')).toUpperCase();
  const outputPath = options.output ? path.resolve(process.cwd(), options.output) : path.resolve(process.cwd(), 'toolveto-badge.svg');

  const svg = generateBadgeSvg(score, tier);
  fs.writeFileSync(outputPath, svg, 'utf8');

  console.log(`\n🛡️ ToolVeto Badge Generated!`);
  console.log(`Tier:   ${tier}`);
  console.log(`Score:  ${score}/100`);
  console.log(`Output: ${outputPath}\n`);
}
