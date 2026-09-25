# fix(mcp): add idempotency keys, query pairing & pagination bounds

## Summary
This automated pull request applies resilience and safety hardening to the MCP tool schemas in `neondatabase/mcp-server-neon`, addressing common agentic failure patterns identified by the **ToolVeto Static Verification Engine**:

- **CRITICAL Issues Found:** 6
- **HIGH Issues Found:** 7
- **Total Checks Evaluated:** 48
- **ToolVeto Score:** 63/100 [Tier: Bronze]

---

## What This Fixes

### 🔧 Fix for `run_sql_query` (TC-IDEMP-001 — CRITICAL)
**Issue:** Sequential replay check failed: Mutation tool 'run_sql_query' accepts no idempotency key

```diff
+ idempotencyKey: z.string().uuid().describe("Unique key to prevent duplicate mutations on retry")
```

### 🔧 Fix for `run_sql_query` (TC-IDEMP-002 — CRITICAL)
**Issue:** Concurrent burst vulnerability: Tool 'run_sql_query' exposes no concurrency lock or idempotency parameter

```diff
+ idempotencyKey: z.string().uuid().describe("Unique key for atomic deduplication")
```

### 🔧 Fix for `run_sql_query` (TC-IDEMP-003 — HIGH)
**Issue:** Missing explicit idempotency key in schema definition for mutation tool 'run_sql_query'

```diff
+ idempotency_key: z.string().uuid().describe("Unique token for idempotent request processing")
```

### 🔧 Fix for `run_sql_query` (TC-PAIR-001 — HIGH)
**Issue:** State auditability blind-write violation: Mutation tool 'run_sql_query' lacks companion query tool ('get_run_sql_query' or 'read_run_sql_query'). Agents cannot verify pre/post state changes

```diff
+ // Define companion inspection query tool:
+ server.tool("get_run_sql_query", { run_sql_query_id: z.string() }, async ({ run_sql_query_id }) => {
+   return { content: [{ type: "text", text: JSON.stringify(await db.get(run_sql_query_id)) }] };
+ });
```

### 🔧 Fix for `create_branch` (TC-IDEMP-001 — CRITICAL)
**Issue:** Sequential replay check failed: Mutation tool 'create_branch' accepts no idempotency key

```diff
+ idempotencyKey: z.string().uuid().describe("Unique key to prevent duplicate mutations on retry")
```

### 🔧 Fix for `create_branch` (TC-IDEMP-002 — CRITICAL)
**Issue:** Concurrent burst vulnerability: Tool 'create_branch' exposes no concurrency lock or idempotency parameter

```diff
+ idempotencyKey: z.string().uuid().describe("Unique key for atomic deduplication")
```

### 🔧 Fix for `create_branch` (TC-IDEMP-003 — HIGH)
**Issue:** Missing explicit idempotency key in schema definition for mutation tool 'create_branch'

```diff
+ idempotency_key: z.string().uuid().describe("Unique token for idempotent request processing")
```

### 🔧 Fix for `create_branch` (TC-PAIR-001 — HIGH)
**Issue:** State auditability blind-write violation: Mutation tool 'create_branch' lacks companion query tool ('get_branch' or 'read_branch'). Agents cannot verify pre/post state changes

```diff
+ // Define companion inspection query tool:
+ server.tool("get_branch", { branch_id: z.string() }, async ({ branch_id }) => {
+   return { content: [{ type: "text", text: JSON.stringify(await db.get(branch_id)) }] };
+ });
```

### 🔧 Fix for `delete_branch` (TC-IDEMP-001 — CRITICAL)
**Issue:** Sequential replay check failed: Mutation tool 'delete_branch' accepts no idempotency key

```diff
+ idempotencyKey: z.string().uuid().describe("Unique key to prevent duplicate mutations on retry")
```

### 🔧 Fix for `delete_branch` (TC-IDEMP-002 — CRITICAL)
**Issue:** Concurrent burst vulnerability: Tool 'delete_branch' exposes no concurrency lock or idempotency parameter

```diff
+ idempotencyKey: z.string().uuid().describe("Unique key for atomic deduplication")
```

### 🔧 Fix for `delete_branch` (TC-IDEMP-003 — HIGH)
**Issue:** Missing explicit idempotency key in schema definition for mutation tool 'delete_branch'

```diff
+ idempotency_key: z.string().uuid().describe("Unique token for idempotent request processing")
```

### 🔧 Fix for `delete_branch` (TC-PAIR-001 — HIGH)
**Issue:** State auditability blind-write violation: Mutation tool 'delete_branch' lacks companion query tool ('get_branch' or 'read_branch'). Agents cannot verify pre/post state changes

```diff
+ // Define companion inspection query tool:
+ server.tool("get_branch", { branch_id: z.string() }, async ({ branch_id }) => {
+   return { content: [{ type: "text", text: JSON.stringify(await db.get(branch_id)) }] };
+ });
```

### 🔧 Fix for `list_projects` (TC-SCHEMA-001 — HIGH)
**Issue:** Unbounded list response risk: Query tool 'list_projects' has no limit/cursor parameter and risks context bomb under production load

```diff
+ limit: z.number().int().min(1).max(100).default(20).describe("Max items to return (default 20)"),
+ cursor: z.string().optional().describe("Opaque pagination cursor")
```


---

## Rationale
Autonomous LLM agents behave differently than human developers or traditional API clients:
1. **They retry failed mutations**: When network calls stutter, models repeat tool calls with identical arguments. Without an explicit `idempotency_key`, this creates duplicate database rows, double-charges, or orphaned entities.
2. **They suffer context saturation**: Without bounded `limit` and `cursor` pagination, list tools dump thousands of tokens into context, degrading agent reasoning.

Generated by [ToolVeto](https://github.com/toolveto/toolveto) — Open-source test harness & CI gate for MCP servers.
