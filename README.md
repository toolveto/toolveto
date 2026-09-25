<p align="center">
  <h1 align="center">🛡️ ToolVeto</h1>
  <p align="center">
    <strong>Block double-charge, crash, and context bombs in CI with a 3-line PR fix.</strong><br>
    <em>Shield stops them in production if you missed them.</em>
  </p>
  <p align="center">
    <a href="#quickstart">Quickstart</a> •
    <a href="#why-toolveto">Why ToolVeto</a> •
    <a href="#the-cli-gate-toolveto-check">CLI Gate</a> •
    <a href="#runtime-protection-toolvetoshield">Shield Runtime</a> •
    <a href="#open-core-architecture">Architecture & Licensing</a>
  </p>
</p>

---

## The Problem

The Model Context Protocol (MCP) standardizes how AI agents call tools. But agents are non-deterministic, hallucinatory clients that retry failed tools, loop endlessly, and exhaust context windows.

MCP servers built like traditional APIs inevitably:
1. **Double-charge** customers when an agent retries a mutation tool after a transient network blip.
2. **Loop 40+ times** when a tool returns ambiguous error strings instead of structured recovery contracts.
3. **Dump 50,000 tokens** into prompt context from an unpaginated list response, blowing up latency and cost.
4. **Crash silently (500)** when an agent passes an unexpected type (e.g. `start_date="tomorrow morning"`).

**ToolVeto tests the server, not the model. And it auto-fixes what it finds.**

---

## Quickstart

Run deterministic checks in **<90 seconds for $0** (zero LLM API keys required):

```bash
npx toolveto@latest check ./my-mcp-server
```

### Sample CI Terminal Output

```text
✗ D1 FAIL — create_payment: idempotency not enforced
  Burst of 10 identical requests → 10 charges created (expected 1)

  Fix (Zod/TypeScript):
  + idempotencyKey: z.string().uuid().describe("Unique key to prevent duplicate charges on retry")

  Fix (Python/FastMCP):
  + idempotency_key: str = Field(..., description="Unique key to prevent duplicate charges on retry")

  [📋 Copy] [🔧 Run: npx toolveto fix --apply]

✗ D2 FAIL — update_record: date="tomorrow morning" → 500 Internal Error
  Fix: return isError:true with "start_date must be YYYY-MM-DD. Received: 'tomorrow morning'"
  [📋 Copy] [🔧 Run: npx toolveto fix --apply]

✓ D2 PASS — list_invoices: returns structured error with param name
✓ D3 PASS — list_invoices: 892 tokens, limit=20 default, has_more ✓

Checks: 4 passed · 2 failed · 0 LLM calls · $0.00 · 47 seconds
```

Auto-apply the suggested AST code patches directly to your source files:

```bash
npx toolveto@latest fix --apply
```

---

## Runtime Protection: `@toolveto/shield`

Can't modify upstream third-party MCP servers (Stripe, GitHub, Linear)? Wrap your server in 5 lines of code to enforce idempotency, loop limits, and token budgets at runtime:

```typescript
import { shield } from '@toolveto/shield';

export default shield(myMcpServer, {
  idempotency: true,                           // SHA-256 payload deduplication
  loopLimit: { count: 5, windowMs: 30_000 },    // Breaks runaway execution loops
  tokenBudget: 4000,                           // Truncates and injects pagination cursors
});
```

---

## Open-Core Architecture & Licensing

ToolVeto operates on a **Two-Repository Topology** to guarantee frictionless open-source developer adoption while strictly safeguarding the proprietary commercial moat (the sealed 60% test battery and runner fleet isolation):

```text
                                  TOOLVETO ECOSYSTEM
                                  
   ┌─────────────────────────────────────────┐     ┌─────────────────────────────────────────┐
   │       PUBLIC REPO: `toolveto`         │     │     PRIVATE REPO: `toolveto-cloud`    │
   │  (GitHub: toolveto/toolveto)        │     │  (GitHub: toolveto/toolveto-cloud)  │
   │                                         │     │                                         │
   │  🎯 Purpose: Dev adoption, CLI, Shield  │     │  🎯 Purpose: SaaS, Fleet, Secret Moat   │
   │  📜 Licenses: MIT, Apache 2.0, BSL 1.1  │     │  📜 License: Proprietary (All Rights)   │
   ├─────────────────────────────────────────┤     ├─────────────────────────────────────────┤
   │  packages/core        (MIT)             │     │  apps/web (Next.js SaaS Dashboard)      │
   │  packages/cli         (MIT)             │     │  apps/api (Control Plane & Billing)     │
   │  packages/shield      (Apache 2.0)      │     │  services/runner-fleet (gVisor/K8s)     │
   │  packages/gateway     (BSL 1.1)         │     │  packages/sealed-corpus (Private 60%)   │
   │  benchmarks/overhead  (MIT)             │     │  packages/failure-lakehouse (ClickHouse)│
   └─────────────────────────────────────────┘     └─────────────────────────────────────────┘
```

| Component | Path | SPDX License | Purpose |
| :--- | :--- | :--- | :--- |
| **`@toolveto/core`** | [`packages/core`](./packages/core) | **MIT** | Deterministic check engine, schema validators, local Docker sandbox adapter |
| **`toolveto`** | [`packages/cli`](./packages/cli) | **MIT** | CLI entrypoint for `toolveto check`, `fix --apply`, and terminal reports |
| **`@toolveto/shield`**| [`packages/shield`](./packages/shield) | **Apache-2.0** | Runtime idempotency deduplication proxy and sliding-window loop limiter |
| **`toolveto-gateway`**| [`packages/gateway`](./packages/gateway) | **BSL-1.1** | Standalone proxy gateway binary for multi-server enterprise deployments (converts to Apache 2.0 after 4 years) |
| **`benchmarks/overhead`**| [`benchmarks/overhead`](./benchmarks/overhead) | **MIT** | Transparent k6 / autocannon latency benchmark test harness |
| **`corpus/published`** | [`corpus/published`](./corpus/published) | **CC-BY-4.0** | 40% public fuzzing and idempotency test fixtures |

---

## Documentation

- [Product Requirements Document (PRD v1.1)](docs/product/PRD-v1.1.md)
- [System Architecture Document](docs/architecture/ARCHITECTURE.md)
- [Scoring Rubric & Evaluation Spec](docs/spec/toolveto_scoring_rubric.md)
- [Go-To-Market & Viral Benchmark Strategy](docs/gtm/GTM_VIRAL_STRATEGY.md)
- [Patent Specifications & Defensive Publications](docs/patents/)

---

## Contributing

We welcome contributions to `@toolveto/core`, `toolveto` CLI, and `@toolveto/shield`. Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for local development instructions.
