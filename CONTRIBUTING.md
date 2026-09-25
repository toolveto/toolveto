# Contributing to ToolVeto

Thank you for your interest in contributing to ToolVeto!

ToolVeto is dedicated to making Model Context Protocol (MCP) servers reliable, safe, and production-grade by preventing double-charges, crashes, and context bombs.

## Repository Overview

- `packages/core`: The deterministic check engine, schema validators, and remediation generator (MIT).
- `packages/cli`: The `toolveto` command-line interface (MIT).
- `packages/shield`: The `@toolveto/shield` runtime deduplication and loop-breaker middleware (Apache 2.0).
- `packages/gateway`: The standalone proxy gateway binary (BSL 1.1).
- `benchmarks/overhead`: Transparent latency and throughput benchmark test suite (MIT).
- `corpus/published`: Base 40% fuzzing and idempotency test fixtures (CC-BY 4.0).

## Development Setup

Prerequisites:
- Node.js >= 20.0.0
- pnpm >= 9.0.0

```bash
# Clone the repository
git clone https://github.com/toolveto/toolveto.git
cd toolveto

# Install workspace dependencies
pnpm install

# Build all packages
pnpm run build

# Run tests and typechecks
pnpm run test
pnpm run typecheck

# Test CLI locally
node packages/cli/dist/bin/toolveto.js check ./sample
```

## Licensing of Contributions

- Contributions to `packages/core`, `packages/cli`, and `benchmarks/overhead` are licensed under the MIT License.
- Contributions to `packages/shield` are licensed under the Apache License 2.0.
- Contributions to `packages/gateway` are licensed under the Business Source License 1.1.
- Contributions to `corpus/published` are licensed under CC-BY 4.0.
