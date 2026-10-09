# @toolveto/shield

Runtime idempotency deduplication, sliding-window loop limiter, and token budget enforcement middleware for Model Context Protocol (MCP) servers.

- **License**: Apache-2.0

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

Distributed under the Apache-2.0 License with an [Explicit Patent Reservation](./LICENSE). For production multi-tenant edge proxying, distributed Redis deduplication mesh, and runtime protocol firewalling, see [ToolVeto Gateway](file:///Users/samirsavla/git/ToolVeto/toolveto/packages/gateway) (BSL-1.1) and ToolVeto Cloud.
