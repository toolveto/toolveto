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
