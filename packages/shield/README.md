# @toolveto/shield

Runtime idempotency deduplication, sliding-window loop limiter, and token budget enforcement middleware for Model Context Protocol (MCP) servers.

- **License**: Business Source License 1.1 (`BUSL-1.1`), converting to Apache-2.0 after 4 years.

## Quickstart

```typescript
import { shield } from '@toolveto/shield';

export default shield(myMcpServer, {
  idempotency: true,                           // SHA-256 payload deduplication
  loopLimit: { count: 5, windowMs: 30_000 },    // Breaks runaway execution loops
  tokenBudget: 4000,                           // Truncates and injects pagination cursors
});
```

## Licensing & Patent Notice

Distributed under the [Business Source License 1.1 (`BUSL-1.1`)](./LICENSE). Free for local development and internal production use protecting your organization's MCP servers; commercial competing hosted/managed gateway offerings require a commercial license. U.S. Patent Pending (`64/176,790` / `TOOLVETO-OMNI-PROV-01` & `TOOLVETO-OMNI-PROV-02`). For standalone multi-upstream enterprise deployments, see [ToolVeto Gateway](../gateway) (`BUSL-1.1`) and ToolVeto Cloud.
