import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { parsePythonSourceForTools } from '../static-extractors.js';
import { badgeCommand, generateBadgeSvg, normalizeTargetSlug } from '../commands/badge.js';

describe('Hugging Face MCP Safety Index — Gradio Extraction, Trust Badges & Benchmark Integrity', () => {
  it('statically extracts Gradio mcp_server=True & NeMo @register_function handlers and strips inline Python # comments', () => {
    const gradioAndNemoPy = `
import gradio as gr

def _start_timer():
    return 0.0

def generate_video(
    image: str,
    # Number of frames decoded at a time! Eats VRAM (reduce if needed)
    num_frames: int = 16,
    device: str = "cuda",
    progress=gr.Progress(),
):
    """Generates a short video clip from an input image prompt."""
    return "out.mp4"

def summarize_docs(query: str, limit: int = 20):
    """Searches and summarizes indexed documents with bounded limit."""
    return []

@register_function(name="nemo_score_claim")
async def score_claim(claim_id: str, dry_run: bool = False):
    """Evaluates claim eligibility inside NVIDIA NeMo Agent Toolkit."""
    return {"ok": True}

btn.click(_start_timer, None, [t0], api_visibility="private").then(
    fn=generate_video,
    inputs=[img],
    outputs=[vid],
    api_name="generate_video",
)
gr.Interface(fn=summarize_docs, inputs=["text", "number"], outputs="json")
demo.launch(mcp_server=True)
`;

    const tools = parsePythonSourceForTools(gradioAndNemoPy, 'app.py');
    const names = tools.map((t) => t.name);
    assert.ok(names.includes('generate_video'), 'Must extract Gradio .then(fn=..., api_name=...) MCP handler');
    assert.ok(names.includes('summarize_docs'), 'Must extract Gradio gr.Interface(fn=...) MCP handler');
    assert.ok(names.includes('nemo_score_claim'), 'Must extract NeMo @register_function handler');
    assert.ok(!names.includes('_start_timer'), 'Must skip private Gradio UI event handlers');

    const vidTool = tools.find((t) => t.name === 'generate_video')!;
    const propKeys = Object.keys(vidTool.inputSchema.properties || {});
    assert.deepStrictEqual(
      propKeys,
      ['image', 'num_frames', 'device'],
      'Inline # comments and gr.Progress() must not leak into extracted JSON schema parameters'
    );
    assert.deepStrictEqual(vidTool.inputSchema.required, ['image']);
    assert.strictEqual(vidTool.inputSchema.properties?.num_frames?.type, 'integer');
  });

  it('generates Hugging Face Space & NVIDIA NIM SVG trust badges with XSS-safe labels and embed markdown', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-hf-badge-'));
    const outSvg = path.join(tmpDir, 'hf-nim-badge.svg');
    const logs: string[] = [];
    const prevLog = console.log;
    console.log = (...args: any[]) => logs.push(args.map(String).join(' '));

    try {
      assert.strictEqual(
        normalizeTargetSlug('https://huggingface.co/spaces/mrfakename/Z-Image-Turbo'),
        'mrfakename/Z-Image-Turbo'
      );

      const snippets = await badgeCommand({
        score: 94,
        tier: 'Platinum',
        output: outSvg,
        huggingface: true,
        space: 'https://huggingface.co/spaces/mrfakename/Z-Image-Turbo',
        profile: 'nvidia-nim',
      });

      assert.ok(snippets, 'badgeCommand must return embed snippets when --huggingface/--space is provided');
      assert.strictEqual(snippets.encodedSlug, 'mrfakename__z-image-turbo');
      assert.ok(
        snippets.badgeUrl.includes('/api/v1/badge/mrfakename__z-image-turbo.svg?label=ToolVeto+NIM'),
        'Badge URL must carry NIM label parameter'
      );
      assert.ok(snippets.githubMarkdown.includes('https://toolveto.ai/r/mrfakename__z-image-turbo'));
      assert.ok(snippets.huggingfaceYamlTags.includes('toolveto-verified'));
      assert.ok(snippets.huggingfaceYamlTags.includes('nvidia-nim-ready'));

      const svg = fs.readFileSync(outSvg, 'utf8');
      assert.ok(svg.startsWith('<svg xmlns="http://www.w3.org/2000/svg"'));
      assert.ok(svg.includes('ToolVeto NIM'));
      assert.ok(svg.includes('PLATINUM 94/100'));

      // Verify XML escaping on hostile custom labels
      const escapedSvg = generateBadgeSvg(88, 'GOLD', '<script>alert("x")</script>');
      assert.ok(!escapedSvg.includes('<script>'), 'Custom badge label must be XML-escaped');
      assert.ok(escapedSvg.includes('&lt;script&gt;'));
    } finally {
      console.log = prevLog;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('publishes consistent, empirically audited Hugging Face MCP Safety Index artifacts and SVG badges', () => {
    const repoRoot = path.resolve(process.cwd(), '../..');
    const candidateRoots = [process.cwd(), path.resolve(process.cwd(), '..'), repoRoot];
    const indexPath = candidateRoots
      .map((r) => path.join(r, 'benchmarks/huggingface-mcp/index.json'))
      .find((p) => fs.existsSync(p));
    assert.ok(indexPath, 'benchmarks/huggingface-mcp/index.json must exist');

    const benchDir = path.dirname(indexPath!);
    const reportPath = path.join(benchDir, 'STATE_OF_OPEN_WEIGHT_AND_FASTMCP_SAFETY_2026.md');
    assert.ok(fs.existsSync(reportPath), 'Benchmark Markdown report must exist');

    const data = JSON.parse(fs.readFileSync(indexPath!, 'utf8'));
    assert.strictEqual(data.schema, 'toolveto-hf-mcp-safety-index/v1');
    assert.ok(Array.isArray(data.spaces) && data.spaces.length >= 25, `Expected >=25 audited HF Spaces, got ${data.spaces?.length}`);
    assert.strictEqual(data.summary.spacesAuditedWithTools, data.spaces.length);

    const recomputedLikes = data.spaces.reduce((acc: number, s: any) => acc + Number(s.likes || 0), 0);
    const recomputedTools = data.spaces.reduce((acc: number, s: any) => acc + Number(s.toolCount || 0), 0);
    const recomputedNimBlocked = data.spaces.filter((s: any) => !s.nvidiaNimProfile?.certified).length;
    assert.strictEqual(data.summary.totalLikes, recomputedLikes);
    assert.strictEqual(data.summary.totalToolsExtracted, recomputedTools);
    assert.strictEqual(data.summary.nimBlockedCount, recomputedNimBlocked);

    for (const space of data.spaces) {
      assert.match(space.commitSha, /^[0-9a-f]{7,40}$/i, `Space ${space.spaceId} must pin a commit SHA`);
      assert.ok(space.toolCount >= 1, `Space ${space.spaceId} must have >=1 statically extracted MCP tool`);
      assert.strictEqual(space.evidenceQuality, 'STATIC-ONLY');
      const badgeSvgPath = path.join(benchDir, 'badges', `${space.encodedSlug}.svg`);
      assert.ok(fs.existsSync(badgeSvgPath), `Missing SVG badge for ${space.spaceId}`);
      const svg = fs.readFileSync(badgeSvgPath, 'utf8');
      assert.ok(svg.startsWith('<svg '), `Invalid SVG badge for ${space.spaceId}`);
    }

    const reportMd = fs.readFileSync(reportPath, 'utf8');
    assert.ok(reportMd.includes('State of Open-Weight & FastMCP Tool Safety'));
    assert.ok(reportMd.includes('--profile nvidia-nim'));
    assert.ok(reportMd.includes('toolveto@latest badge --huggingface'));
  });
});
