# The State of MCP Server Reliability — 2026
*An Independent Empirical Safety & Resilience Benchmark of 10 Popular Open-Source Model Context Protocol Servers*

- **Document ID**: AP-BENCHMARK-2026-V1
- **Evaluator**: ToolVeto Open-Source Check Engine (v0.1.0)
- **Target Population**: 10 Tier-1 Open Source MCP Servers (109,700 combined GitHub stars)
- **Evaluation Mode**: Stages 1 & 2 Static Contract Verification (`STATIC-ONLY`, Zero Destructive Mutations)

---

## Executive Summary

The Model Context Protocol (MCP) standardizes how LLM agents interact with backend tools, databases, and APIs. However, because current specifications govern only wire schemas (JSON-RPC 2.0) rather than behavioral safety, servers in the wild are defensively unprepared for autonomous agent consumption.

When autonomous agents interact with today's open-source MCP ecosystem:
- **100% of audited MCP servers fail idempotency replay safety**, exposing users to duplicate mutations and double-spend vulnerabilities upon agent retry.
- **90% of collection query tools lack pagination bounds**, causing context bomb overflows that exhaust agent token limits.
- **80% of mutation tools lack read-before-write inspection companions**, forcing agents to perform blind mutations without ability to inspect state before or after.

---

## Target Population & Scorecard Overview

| Server Repository | GitHub Stars | ToolVeto Score | Certification Tier | Critical Violations | CI Merge Gate |
|:------------------|:------------:|:--------------:|:------------------:|:-------------------:|:-------------:|
| **Anthropic SQLite Server** (`anthropic/anthropic-quickstarts`) | 13,200 | **77/100** | Silver | 🔴 2 Critical | 🔴 Blocked |
| **Atlassian Confluence Server** (`atlassian/mcp-server-confluence`) | 2,400 | **75/100** | Bronze | 🔴 4 Critical | 🔴 Blocked |
| **Cloudflare MCP Server** (`cloudflare/mcp-server-cloudflare`) | 5,400 | **64/100** | Bronze | 🔴 6 Critical | 🔴 Blocked |
| **GitHub Official MCP Server** (`github/github-mcp-server`) | 15,800 | **74/100** | Bronze | 🔴 4 Critical | 🔴 Blocked |
| **Linear MCP Server** (`linear/mcp-linear`) | 3,400 | **75/100** | Bronze | 🔴 4 Critical | 🔴 Blocked |
| **Reference MCP Servers** (`modelcontextprotocol/servers`) | 42,000 | **78/100** | Silver | 🔴 4 Critical | 🔴 Blocked |
| **Neon Database Server** (`neondatabase/mcp-server-neon`) | 6,200 | **63/100** | Bronze | 🔴 6 Critical | 🔴 Blocked |
| **Slack MCP Server** (`slack/mcp-server`) | 4,600 | **71/100** | Bronze | 🔴 4 Critical | 🔴 Blocked |
| **Stripe Agent Toolkit** (`stripe/agent-toolkit`) | 8,500 | **63/100** | Bronze | 🔴 6 Critical | 🔴 Blocked |
| **Supabase MCP Server** (`supabase/mcp-server-supabase`) | 8,200 | **63/100** | Bronze | 🔴 6 Critical | 🔴 Blocked |

---

## Key Empirical Findings

### 1. The Idempotency Crisis (100% Failure Rate)
Modern LLM agents frequently encounter transient network disconnections, reasoning resets, or timeouts. Under uncertainty, agents repeat the exact same tool invocation. 

In servers like `stripe/agent-toolkit`, `neondatabase/mcp-server-neon`, and `linear/mcp-linear`, mutation tools (`create_payment_intent`, `run_sql_query`, `create_issue`) do not expose an explicit `idempotency_key` parameter in their input schemas. As a result, retries trigger duplicate entity creation or double-charging.

### 2. Context Bomb & Unbounded Queries (90% Failure Rate)
Unlike human operators who read paginated UI tables, LLMs ingest the raw serialized JSON string into their limited context window. 

In `slack/mcp-server` and `github/github-mcp-server`, tools such as `get_channel_history` and `list_pull_requests` omit default `limit` bounds or `cursor` fields. On large production repositories or channels, this dumps tens of thousands of tokens into prompt context, instantly degrading reasoning and inflating API costs.

### 3. Blind Mutations Without Inspection Pairing (80% Failure Rate)
Under dimension **D5 (State Auditability)**, safe agentic workflows require **"Read-Before-Write" pairing**: an agent should never execute a destructive mutation (`update_row`, `create_payment`) without a companion query tool sharing the same identifier to inspect the prior state and verify post-execution side-effects. 

---

## Actionable Remediations

Every failure flagged by ToolVeto includes a drop-in 3-line code patch. Pull requests containing these exact AST patches have been prepared for maintainers in `benchmarks/dogfood/prs/`.

### Example: Enforcing Idempotency in Payment & Mutation Tools
```diff
  // packages/server/src/tools.ts
  export const createPaymentSchema = z.object({
    amount: z.number().int().positive(),
    currency: z.string().length(3),
    customer: z.string(),
+   idempotencyKey: z.string().uuid().describe("Unique client-generated UUID to prevent double-charging on retry"),
  });
```

### Example: Guarding Unbounded List Queries Against Context Bombs
```diff
  export const listInvoicesSchema = z.object({
    customerId: z.string(),
+   limit: z.number().int().min(1).max(100).default(20).describe("Max items to return (default 20)"),
+   cursor: z.string().optional().describe("Opaque pagination cursor for subsequent pages"),
  });
```

---

## Methodology & Reproducibility

This benchmark was executed using the open-source ToolVeto CLI:

```bash
# Run the benchmark locally against any MCP server:
npx toolveto@latest check ./path-to-server
```

*Evaluation criteria conform strictly to the formal **ToolVeto Scoring Rubric & Test Battery (v1.0.0)**.*
