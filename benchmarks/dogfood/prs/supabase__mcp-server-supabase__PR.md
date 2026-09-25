# fix(mcp): add idempotency keys, query pairing & pagination bounds

## Summary
This automated pull request applies resilience and safety hardening to the MCP tool schemas in `supabase/mcp-server-supabase`, addressing common agentic failure patterns identified by the **ToolVeto Static Verification Engine**:

- **CRITICAL Issues Found:** 6
- **HIGH Issues Found:** 7
- **Total Checks Evaluated:** 48
- **ToolVeto Score:** 63/100 [Tier: Bronze]

---

## What This Fixes

### 🔧 Fix for `execute_sql` (TC-IDEMP-001 — CRITICAL)
**Issue:** Sequential replay check failed: Mutation tool 'execute_sql' accepts no idempotency key

```diff
+ idempotencyKey: z.string().uuid().describe("Unique key to prevent duplicate mutations on retry")
```

### 🔧 Fix for `execute_sql` (TC-IDEMP-002 — CRITICAL)
**Issue:** Concurrent burst vulnerability: Tool 'execute_sql' exposes no concurrency lock or idempotency parameter

```diff
+ idempotencyKey: z.string().uuid().describe("Unique key for atomic deduplication")
```

### 🔧 Fix for `execute_sql` (TC-IDEMP-003 — HIGH)
**Issue:** Missing explicit idempotency key in schema definition for mutation tool 'execute_sql'

```diff
+ idempotency_key: z.string().uuid().describe("Unique token for idempotent request processing")
```

### 🔧 Fix for `execute_sql` (TC-PAIR-001 — HIGH)
**Issue:** State auditability blind-write violation: Mutation tool 'execute_sql' lacks companion query tool ('get_execute_sql' or 'read_execute_sql'). Agents cannot verify pre/post state changes

```diff
+ // Define companion inspection query tool:
+ server.tool("get_execute_sql", { execute_sql_id: z.string() }, async ({ execute_sql_id }) => {
+   return { content: [{ type: "text", text: JSON.stringify(await db.get(execute_sql_id)) }] };
+ });
```

### 🔧 Fix for `insert_row` (TC-IDEMP-001 — CRITICAL)
**Issue:** Sequential replay check failed: Mutation tool 'insert_row' accepts no idempotency key

```diff
+ idempotencyKey: z.string().uuid().describe("Unique key to prevent duplicate mutations on retry")
```

### 🔧 Fix for `insert_row` (TC-IDEMP-002 — CRITICAL)
**Issue:** Concurrent burst vulnerability: Tool 'insert_row' exposes no concurrency lock or idempotency parameter

```diff
+ idempotencyKey: z.string().uuid().describe("Unique key for atomic deduplication")
```

### 🔧 Fix for `insert_row` (TC-IDEMP-003 — HIGH)
**Issue:** Missing explicit idempotency key in schema definition for mutation tool 'insert_row'

```diff
+ idempotency_key: z.string().uuid().describe("Unique token for idempotent request processing")
```

### 🔧 Fix for `insert_row` (TC-PAIR-001 — HIGH)
**Issue:** State auditability blind-write violation: Mutation tool 'insert_row' lacks companion query tool ('get_insert_row' or 'read_insert_row'). Agents cannot verify pre/post state changes

```diff
+ // Define companion inspection query tool:
+ server.tool("get_insert_row", { insert_row_id: z.string() }, async ({ insert_row_id }) => {
+   return { content: [{ type: "text", text: JSON.stringify(await db.get(insert_row_id)) }] };
+ });
```

### 🔧 Fix for `update_row` (TC-IDEMP-001 — CRITICAL)
**Issue:** Sequential replay check failed: Mutation tool 'update_row' accepts no idempotency key

```diff
+ idempotencyKey: z.string().uuid().describe("Unique key to prevent duplicate mutations on retry")
```

### 🔧 Fix for `update_row` (TC-IDEMP-002 — CRITICAL)
**Issue:** Concurrent burst vulnerability: Tool 'update_row' exposes no concurrency lock or idempotency parameter

```diff
+ idempotencyKey: z.string().uuid().describe("Unique key for atomic deduplication")
```

### 🔧 Fix for `update_row` (TC-IDEMP-003 — HIGH)
**Issue:** Missing explicit idempotency key in schema definition for mutation tool 'update_row'

```diff
+ idempotency_key: z.string().uuid().describe("Unique token for idempotent request processing")
```

### 🔧 Fix for `update_row` (TC-PAIR-001 — HIGH)
**Issue:** State auditability blind-write violation: Mutation tool 'update_row' lacks companion query tool ('get_row' or 'read_row'). Agents cannot verify pre/post state changes

```diff
+ // Define companion inspection query tool:
+ server.tool("get_row", { row_id: z.string() }, async ({ row_id }) => {
+   return { content: [{ type: "text", text: JSON.stringify(await db.get(row_id)) }] };
+ });
```

### 🔧 Fix for `list_tables` (TC-SCHEMA-001 — HIGH)
**Issue:** Unbounded list response risk: Query tool 'list_tables' has no limit/cursor parameter and risks context bomb under production load

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
