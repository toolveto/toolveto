# toolveto-gateway

Enterprise MCP Reverse Proxy with centralized idempotency enforcement, loop shielding, and token budgeting.

- **License**: Business Source License 1.1 (BSL-1.1), converting to Apache-2.0 after 4 years.
- **Docker Deployment**:
  ```bash
  docker run -p 8080:8080 -e UPSTREAM_URL="http://mcp-server:3000" toolveto/gateway:latest
  ```
