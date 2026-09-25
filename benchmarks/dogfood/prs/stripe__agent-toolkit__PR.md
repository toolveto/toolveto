# fix(mcp): add idempotency keys, query pairing & pagination bounds

## Summary
This automated pull request applies resilience and safety hardening to the MCP tool schemas in `stripe/agent-toolkit`, addressing common agentic failure patterns identified by the **ToolVeto Static Verification Engine**:

- **CRITICAL Issues Found:** 6
- **HIGH Issues Found:** 7
- **Total Checks Evaluated:** 48
- **ToolVeto Score:** 63/100 [Tier: Bronze]

---

## What This Fixes

### 🔧 Fix for `create_payment_intent` (TC-IDEMP-001 — CRITICAL)
**Issue:** Sequential replay check failed: Mutation tool 'create_payment_intent' accepts no idempotency key

```diff
+ idempotencyKey: z.string().uuid().describe("Unique key to prevent duplicate mutations on retry")
```

### 🔧 Fix for `create_payment_intent` (TC-IDEMP-002 — CRITICAL)
**Issue:** Concurrent burst vulnerability: Tool 'create_payment_intent' exposes no concurrency lock or idempotency parameter

```diff
+ idempotencyKey: z.string().uuid().describe("Unique key for atomic deduplication")
```

### 🔧 Fix for `create_payment_intent` (TC-IDEMP-003 — HIGH)
**Issue:** Missing explicit idempotency key in schema definition for mutation tool 'create_payment_intent'

```diff
+ idempotency_key: z.string().uuid().describe("Unique token for idempotent request processing")
```

### 🔧 Fix for `create_payment_intent` (TC-PAIR-001 — HIGH)
**Issue:** State auditability blind-write violation: Mutation tool 'create_payment_intent' lacks companion query tool ('get_payment_intent' or 'read_payment_intent'). Agents cannot verify pre/post state changes

```diff
+ // Define companion inspection query tool:
+ server.tool("get_payment_intent", { payment_intent_id: z.string() }, async ({ payment_intent_id }) => {
+   return { content: [{ type: "text", text: JSON.stringify(await db.get(payment_intent_id)) }] };
+ });
```

### 🔧 Fix for `create_customer` (TC-IDEMP-001 — CRITICAL)
**Issue:** Sequential replay check failed: Mutation tool 'create_customer' accepts no idempotency key

```diff
+ idempotencyKey: z.string().uuid().describe("Unique key to prevent duplicate mutations on retry")
```

### 🔧 Fix for `create_customer` (TC-IDEMP-002 — CRITICAL)
**Issue:** Concurrent burst vulnerability: Tool 'create_customer' exposes no concurrency lock or idempotency parameter

```diff
+ idempotencyKey: z.string().uuid().describe("Unique key for atomic deduplication")
```

### 🔧 Fix for `create_customer` (TC-IDEMP-003 — HIGH)
**Issue:** Missing explicit idempotency key in schema definition for mutation tool 'create_customer'

```diff
+ idempotency_key: z.string().uuid().describe("Unique token for idempotent request processing")
```

### 🔧 Fix for `create_customer` (TC-PAIR-001 — HIGH)
**Issue:** State auditability blind-write violation: Mutation tool 'create_customer' lacks companion query tool ('get_customer' or 'read_customer'). Agents cannot verify pre/post state changes

```diff
+ // Define companion inspection query tool:
+ server.tool("get_customer", { customer_id: z.string() }, async ({ customer_id }) => {
+   return { content: [{ type: "text", text: JSON.stringify(await db.get(customer_id)) }] };
+ });
```

### 🔧 Fix for `list_charges` (TC-SCHEMA-001 — HIGH)
**Issue:** Unbounded list response risk: Query tool 'list_charges' has no limit/cursor parameter and risks context bomb under production load

```diff
+ limit: z.number().int().min(1).max(100).default(20).describe("Max items to return (default 20)"),
+ cursor: z.string().optional().describe("Opaque pagination cursor")
```

### 🔧 Fix for `refund_charge` (TC-IDEMP-001 — CRITICAL)
**Issue:** Sequential replay check failed: Mutation tool 'refund_charge' accepts no idempotency key

```diff
+ idempotencyKey: z.string().uuid().describe("Unique key to prevent duplicate mutations on retry")
```

### 🔧 Fix for `refund_charge` (TC-IDEMP-002 — CRITICAL)
**Issue:** Concurrent burst vulnerability: Tool 'refund_charge' exposes no concurrency lock or idempotency parameter

```diff
+ idempotencyKey: z.string().uuid().describe("Unique key for atomic deduplication")
```

### 🔧 Fix for `refund_charge` (TC-IDEMP-003 — HIGH)
**Issue:** Missing explicit idempotency key in schema definition for mutation tool 'refund_charge'

```diff
+ idempotency_key: z.string().uuid().describe("Unique token for idempotent request processing")
```

### 🔧 Fix for `refund_charge` (TC-PAIR-001 — HIGH)
**Issue:** State auditability blind-write violation: Mutation tool 'refund_charge' lacks companion query tool ('get_refund_charge' or 'read_refund_charge'). Agents cannot verify pre/post state changes

```diff
+ // Define companion inspection query tool:
+ server.tool("get_refund_charge", { refund_charge_id: z.string() }, async ({ refund_charge_id }) => {
+   return { content: [{ type: "text", text: JSON.stringify(await db.get(refund_charge_id)) }] };
+ });
```


---

## Rationale
Autonomous LLM agents behave differently than human developers or traditional API clients:
1. **They retry failed mutations**: When network calls stutter, models repeat tool calls with identical arguments. Without an explicit `idempotency_key`, this creates duplicate database rows, double-charges, or orphaned entities.
2. **They suffer context saturation**: Without bounded `limit` and `cursor` pagination, list tools dump thousands of tokens into context, degrading agent reasoning.

Generated by [ToolVeto](https://github.com/toolveto/toolveto) — Open-source test harness & CI gate for MCP servers.
