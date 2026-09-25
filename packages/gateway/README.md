# toolveto-gateway

Enterprise MCP Reverse Proxy with multi-upstream routing, centralized idempotency enforcement, loop shielding, token budgeting, and prompt injection defense.

- **License**: Business Source License 1.1 (BSL-1.1), converting to Apache-2.0 after 4 years.
- **Docker Deployment**:
  ```bash
  docker run -p 8080:8080 -v $(pwd)/toolveto-gateway.yml:/app/toolveto-gateway.yml toolveto/gateway:latest
  ```

## Configuration via `toolveto-gateway.yml`

The gateway automatically resolves `toolveto-gateway.yml` or `toolveto-gateway.yaml` from the current working directory (`process.cwd()`), root repository, or config paths.

```yaml
version: '1'
port: 8080
defaultPolicy: standard

auth:
  type: bearer
  secret: "${TOOLVETO_GATEWAY_SECRET}"

upstreams:
  stripe:
    url: "https://mcp.stripe.com/v1"
    prefix: "/stripe"
    toolPrefix: "stripe_"
    policy: strict
    authHeader: "Bearer ${STRIPE_API_KEY}"

  neon:
    url: "https://mcp.neon.tech/v1"
    prefix: "/neon"
    toolPrefix: "neon_"
    policy: standard

  default:
    url: "http://localhost:3000"
    policy: standard
```

## Observability & Endpoints

- `GET /health` — Service health, active upstreams, policies, and metrics summary.
- `GET /metrics` — Prometheus metrics (and JSON via `Accept: application/json` or `?format=json`).
- `POST /mcp` or `POST /:prefix/mcp` — JSON-RPC reverse proxy endpoint protected by Shield.
