# State of Open-Weight & FastMCP Tool Safety — Hugging Face MCP Safety Index (2026)

*An Independent, Reproducible Static Security & NVIDIA NIM KV-Cache Benchmark of Public Hugging Face MCP Spaces*

- **Report Date**: 2026-11-28
- **Evaluator**: ToolVeto Open-Source Deterministic Engine (`v0.2.0`, 41 Checks + `--profile nvidia-nim`)
- **Methodology**: Zero-code-execution static AST & schema extraction (`STATIC-ONLY`) at pinned Hugging Face Space commit SHAs. No Spaces were mutated, invoked, or fuzz-attacked over the network.
- **Scope**: Discovered **80** active Hugging Face `mcp-server` / FastMCP Spaces, statically extracted real MCP tool contracts from **30** Spaces (**39,686** combined likes, **109** extracted MCP tools).

---

## Executive Summary

Open-weight model Spaces and FastMCP servers hosted on Hugging Face Hub are rapidly becoming the default tool catalog for autonomous agents running on NVIDIA NIM, NeMo Agent Toolkit, Cursor, and Claude. Because Gradio `mcp_server=True` and FastMCP expose Python functions directly as MCP tools without deterministic safety gates, production agents inherit four systemic failure modes:

| Benchmark Metric | Empirical Result |
| :--- | :---: |
| **Hugging Face MCP Spaces Empirically Audited** | **30** (39,686 likes · 109 tools) |
| **Average ToolVeto Reliability Score** | **90.4/100** |
| **NVIDIA NIM Certification Gate Block Rate (`--profile nvidia-nim`)** | **23/30 (77%)** |
| **Elevated / Critical KV-Cache Eviction Risk** | **30/30 (100%)** |
| **Spaces With Static Schema / Hygiene Failures** | **22/30 (73%)** |
| **Spaces Triggering Security / SSRF / Transport Warnings or Failures** | **2/30 (7%)** |

---

## Hugging Face MCP Safety Index Leaderboard

| # | Hugging Face Space (Pinned SHA) | Likes | Framework | Tools | ToolVeto Score | NVIDIA NIM Gate | Top Finding |
| :-: | :--- | ---: | :--- | ---: | :---: | :---: | :--- |
| 1 | [**mrfakename/Z-Image-Turbo**](https://huggingface.co/spaces/mrfakename/Z-Image-Turbo) (`705280db`) | 3,972 | Gradio MCP (mcp_server=True) | 2 | **91/100** (Gold) | 🟢 Certified | None |
| 2 | [**zerogpu-aoti/wan2-2-fp8da-aoti-faster**](https://huggingface.co/spaces/zerogpu-aoti/wan2-2-fp8da-aoti-faster) (`1ff7432a`) | 3,936 | Gradio MCP (mcp_server=True) | 1 | **88/100** (Gold) | 🔴 CRITICAL KV Risk | `TC-SCHEMA-002` (MEDIUM) |
| 3 | [**r3gm/wan2-2-fp8da-aoti-preview**](https://huggingface.co/spaces/r3gm/wan2-2-fp8da-aoti-preview) (`4e6a3327`) | 3,357 | Gradio MCP (mcp_server=True) | 1 | **88/100** (Gold) | 🔴 CRITICAL KV Risk | `TC-SCHEMA-002` (MEDIUM) |
| 4 | [**not-lain/background-removal**](https://huggingface.co/spaces/not-lain/background-removal) (`448a02ef`) | 3,001 | Gradio MCP (mcp_server=True) | 3 | **91/100** (Gold) | 🔴 CRITICAL KV Risk | `TC-SCHEMA-002` (MEDIUM) |
| 5 | [**prithivMLmods/Qwen-Image-Edit-2511-LoRAs-Fast**](https://huggingface.co/spaces/prithivMLmods/Qwen-Image-Edit-2511-LoRAs-Fast) (`e4a4b5ba`) | 2,789 | FastMCP + Gradio MCP | 1 | **93/100** (Platinum) | 🟢 Certified | None |
| 6 | [**linoyts/Qwen-Image-Edit-Angles**](https://huggingface.co/spaces/linoyts/Qwen-Image-Edit-Angles) (`0f34ae42`) | 2,280 | Gradio MCP (mcp_server=True) | 8 | **91/100** (Gold) | 🔴 CRITICAL KV Risk | `TC-SCHEMA-002` (MEDIUM) |
| 7 | [**r3gm/wan2-2-fp8da-aoti-preview2**](https://huggingface.co/spaces/r3gm/wan2-2-fp8da-aoti-preview2) (`72e4012e`) | 2,188 | Gradio MCP (mcp_server=True) | 1 | **88/100** (Gold) | 🔴 CRITICAL KV Risk | `TC-SCHEMA-002` (MEDIUM) |
| 8 | [**mediasynthesismuseum/stable-video-diffusion**](https://huggingface.co/spaces/mediasynthesismuseum/stable-video-diffusion) (`168a5cb3`) | 2,061 | Gradio MCP (mcp_server=True) | 1 | **88/100** (Gold) | 🔴 CRITICAL KV Risk | `TC-SCHEMA-002` (MEDIUM) |
| 9 | [**Tongyi-MAI/Z-Image-Turbo**](https://huggingface.co/spaces/Tongyi-MAI/Z-Image-Turbo) (`768cb50d`) | 1,948 | Gradio MCP (mcp_server=True) | 1 | **90/100** (Gold) | 🔴 CRITICAL KV Risk | `TC-SCHEMA-002` (MEDIUM) |
| 10 | [**ResembleAI/Chatterbox**](https://huggingface.co/spaces/ResembleAI/Chatterbox) (`9d5bf071`) | 1,770 | Gradio MCP (mcp_server=True) | 1 | **90/100** (Gold) | 🔴 CRITICAL KV Risk | `TC-SCHEMA-002` (MEDIUM) |
| 11 | [**kulkas2pintu/wan777**](https://huggingface.co/spaces/kulkas2pintu/wan777) (`720f97e5`) | 1,725 | Gradio MCP (mcp_server=True) | 1 | **88/100** (Gold) | 🔴 CRITICAL KV Risk | `TC-SCHEMA-002` (MEDIUM) |
| 12 | [**prithivMLmods/FireRed-Image-Edit-1.0-Fast**](https://huggingface.co/spaces/prithivMLmods/FireRed-Image-Edit-1.0-Fast) (`62551d83`) | 1,652 | FastMCP + Gradio MCP | 1 | **93/100** (Platinum) | 🟢 Certified | None |
| 13 | [**Lightricks/ltx-video-distilled**](https://huggingface.co/spaces/Lightricks/ltx-video-distilled) (`8a42e934`) | 1,638 | Gradio MCP (mcp_server=True) | 3 | **84/100** (Gold) | 🔴 CRITICAL KV Risk | `TC-SCHEMA-002` (MEDIUM) |
| 14 | [**multimodalart/wan2-1-fast**](https://huggingface.co/spaces/multimodalart/wan2-1-fast) (`d8ad2caa`) | 1,634 | Gradio MCP (mcp_server=True) | 1 | **88/100** (Gold) | 🔴 CRITICAL KV Risk | `TC-SCHEMA-002` (MEDIUM) |
| 15 | [**fffiloni/CLIP-Interrogator-2**](https://huggingface.co/spaces/fffiloni/CLIP-Interrogator-2) (`2e641f4f`) | 1,370 | Gradio MCP (mcp_server=True) | 1 | **94/100** (Platinum) | 🟢 Certified | None |
| 16 | [**prithivMLmods/FLUX-LoRA-DLC**](https://huggingface.co/spaces/prithivMLmods/FLUX-LoRA-DLC) (`6f810653`) | 1,280 | Gradio MCP (mcp_server=True) | 1 | **90/100** (Gold) | 🔴 CRITICAL KV Risk | `TC-SCHEMA-002` (MEDIUM) |
| 17 | [**hugging-apps/bfs-best-face-swap**](https://huggingface.co/spaces/hugging-apps/bfs-best-face-swap) (`eae055aa`) | 1,131 | Gradio MCP (mcp_server=True) | 1 | **90/100** (Gold) | 🔴 CRITICAL KV Risk | `TC-SCHEMA-002` (MEDIUM) |
| 18 | [**prithivMLmods/Qwen-Image-Edit-2509-LoRAs-Fast**](https://huggingface.co/spaces/prithivMLmods/Qwen-Image-Edit-2509-LoRAs-Fast) (`a0a8e1aa`) | 964 | FastMCP + Gradio MCP | 1 | **93/100** (Platinum) | 🟢 Certified | None |
| 19 | [**Agents-MCP-Hackathon/AI-Marketing-Content-Creator**](https://huggingface.co/spaces/Agents-MCP-Hackathon/AI-Marketing-Content-Creator) (`e740d725`) | 203 | FastMCP + Gradio MCP | 17 | **92/100** (Gold) | 🔴 CRITICAL KV Risk | `TC-SCHEMA-002` (MEDIUM) |
| 20 | [**Agents-MCP-Hackathon/consilium_mcp**](https://huggingface.co/spaces/Agents-MCP-Hackathon/consilium_mcp) (`90804546`) | 137 | Gradio MCP (mcp_server=True) | 6 | **90/100** (Gold) | 🔴 CRITICAL KV Risk | `TC-SCHEMA-002` (MEDIUM) |
| 21 | [**MCP-1st-Birthday/anim-lab-ai**](https://huggingface.co/spaces/MCP-1st-Birthday/anim-lab-ai) (`b76fe287`) | 130 | Gradio MCP (mcp_server=True) | 3 | **90/100** (Gold) | 🔴 CRITICAL KV Risk | `TC-SEC-004` (HIGH) |
| 22 | [**Agents-MCP-Hackathon/web-scraper**](https://huggingface.co/spaces/Agents-MCP-Hackathon/web-scraper) (`11116c60`) | 119 | Gradio MCP (mcp_server=True) | 5 | **91/100** (Gold) | 🔴 ELEVATED KV Risk | None |
| 23 | [**mcp-tools/Z-Image-Turbo**](https://huggingface.co/spaces/mcp-tools/Z-Image-Turbo) (`523314ae`) | 76 | Gradio MCP (mcp_server=True) | 1 | **90/100** (Gold) | 🔴 CRITICAL KV Risk | `TC-SCHEMA-002` (MEDIUM) |
| 24 | [**MCP-1st-Birthday/voicekit**](https://huggingface.co/spaces/MCP-1st-Birthday/voicekit) (`7ae2c28f`) | 54 | Gradio MCP (mcp_server=True) | 6 | **93/100** (Platinum) | 🔴 CRITICAL KV Risk | `TC-SCHEMA-002` (MEDIUM) |
| 25 | [**Agents-MCP-Hackathon/ShallowCodeResearch**](https://huggingface.co/spaces/Agents-MCP-Hackathon/ShallowCodeResearch) (`ba636af6`) | 51 | Gradio MCP (mcp_server=True) | 12 | **93/100** (Gold) | 🔴 CRITICAL KV Risk | `TC-SEC-004` (HIGH) |
| 26 | [**Agents-MCP-Hackathon/doc-mcp**](https://huggingface.co/spaces/Agents-MCP-Hackathon/doc-mcp) (`831be6f0`) | 51 | Gradio MCP (mcp_server=True) | 18 | **89/100** (Gold) | 🔴 CRITICAL KV Risk | `TC-SCHEMA-002` (MEDIUM) |
| 27 | [**burtenshaw/autotrain-mcp**](https://huggingface.co/spaces/burtenshaw/autotrain-mcp) (`41036579`) | 47 | Gradio MCP (mcp_server=True) | 6 | **91/100** (Gold) | 🔴 CRITICAL KV Risk | `TC-SCHEMA-002` (MEDIUM) |
| 28 | [**aiqcamp/MCP-kokoro**](https://huggingface.co/spaces/aiqcamp/MCP-kokoro) (`7a963992`) | 43 | Gradio MCP (mcp_server=True) | 1 | **94/100** (Platinum) | 🟢 Certified | None |
| 29 | [**Agents-MCP-Hackathon/universal-file-converter**](https://huggingface.co/spaces/Agents-MCP-Hackathon/universal-file-converter) (`252e4a86`) | 41 | Gradio MCP (mcp_server=True) | 2 | **91/100** (Gold) | 🟢 Certified | None |
| 30 | [**Agents-MCP-Hackathon/multi-agent_deep-research**](https://huggingface.co/spaces/Agents-MCP-Hackathon/multi-agent_deep-research) (`8e728b96`) | 38 | Gradio MCP (mcp_server=True) | 2 | **91/100** (Gold) | 🔴 CRITICAL KV Risk | `TC-SCHEMA-002` (MEDIUM) |

---

## Most Prevalent Failure Patterns Across Hugging Face MCP Spaces

| Check ID | Severity | Affected Spaces | Description |
| :--- | :---: | :---: | :--- |
| `TC-SCHEMA-002` | MEDIUM | 22/30 (73%) | Description entropy failure: Tool 'generate_video' description is too terse (0 chars, minimum 30 required for reliable LLM tool steering) |
| `TC-SEC-004` | HIGH | 2/30 (7%) | Tool 'generate_animation' exposes unconstrained command/code/SQL string sink(s) [code] without enum/pattern allowlist. |
| `TC-SCHEMA-001` | HIGH | 1/30 (3%) | Unbounded list response risk: Query tool 'list_available_docs' has no limit/cursor parameter and risks context bomb under production load |
| `TC-STDIO-001` | HIGH | 1/30 (3%) | Stdio MCP stdout pollution detected in 1 file(s): writing console.log/print/fmt.Print corrupts JSON-RPC framing. |

### Why This Matters for NVIDIA NIM & Open-Weight Inference Economics
1. **KV-Cache Prefix Eviction (D3 Context Hygiene)**: Unbounded scrape/search/list handlers and missing schema bounds dump tens of thousands of unpaginated tokens into agent context, evicting shared KV-cache prefixes on NVIDIA NIM / vLLM clusters and multiplying per-task GPU token spend by 10x–40x.
2. **Ambiguous Tool Contracts & Runaway Retry Loops (D2 Error Feedback & D4 Descriptions)**: Gradio `mcp_server=True` handlers frequently export raw Python functions without docstrings, type descriptions, or `additionalProperties: false`, causing open-weight tool-calling models (Nemotron, Llama, Qwen) to guess invalid parameters and loop repeatedly.
3. **Missing Mutation Safety & SSRF Guards (D1 / D4)**: Public Spaces accepting arbitrary `url` parameters or mutating remote state rarely declare `idempotency_key`, `readOnlyHint`, or outbound SSRF allowlists.

---

## Claim Your Free GitHub & Hugging Face Space Trust Badge

Any Hugging Face Space or FastMCP maintainer can reproduce their scorecard locally in under 5 seconds ($0, zero LLM API keys), auto-fix pagination & idempotency contracts, and embed a free Trust Badge in their `README.md`:

```bash
# 1. Audit locally with the NVIDIA NIM GPU/KV-Cache profile
npx toolveto@latest check . --profile nvidia-nim

# 2. Auto-fix FastMCP & NeMo Agent Toolkit handlers in-place
npx toolveto@latest fix . --lang fastmcp --apply

# 3. Export NVIDIA OpenShell & NeMo Guardrails policies
npx toolveto@latest export-policy . --format nvidia-openshell -o openshell-policy.yaml
npx toolveto@latest export-policy . --format nemo-guardrails -o ./nemo-guardrails

# 4. Generate a free SVG badge + Hugging Face Space README Markdown snippet
npx toolveto@latest badge --huggingface --space mrfakename/Z-Image-Turbo --profile nvidia-nim
```

### Example Hugging Face Space `README.md` Badge Embed
```markdown
[![ToolVeto NVIDIA NIM Certified (91/100)](https://toolveto.ai/api/v1/badge/mrfakename__z-image-turbo.svg?label=ToolVeto+NIM)](https://toolveto.ai/r/mrfakename__z-image-turbo)
```

---

*Reproduce this entire benchmark dataset anytime with `node scripts/scan-hf-mcp-index.mjs` inside [`toolveto/toolveto`](https://github.com/toolveto/toolveto). Machine-readable dataset: [`benchmarks/huggingface-mcp/index.json`](./index.json).*
