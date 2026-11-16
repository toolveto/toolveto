# @toolveto/core

The core engine for deterministic chaos testing, schema validation, and remediation generation for Model Context Protocol (MCP) servers.

- **License**: MIT
- **Features**:
  - **41 deterministic `toolveto check` rules** across D1–D5 (plus 4 `toolveto doctor` IDE supply-chain checks = **45 Free deterministic checks** across 18 invariant families; **65** total checks with Cloud SAST, Sealed Corpus & Fleet Governance)
  - D1 Idempotency burst and replay testers
  - D2 Deterministic type-inversion, stdio framing (`TC-STDIO-001`), HTTP transport auth (`TC-HTTP-001`), and error handling fuzzers
  - D3-lite Context hygiene, pagination/array bounds (`TC-SCHEMA-004`), parameter constraint (`TC-SCHEMA-005`), and rug-pull (`TC-CTX-002`) linters
  - D4/D5 Annotation consistency (`TC-ANNOTATION-001/002`), static `outputSchema` (`TC-OUTPUT-002`), resource template (`TC-RES-003`), and prompt injection/homoglyph guards (`TC-SEC-002..004`)
  - Zero-exec static extraction + actionable copy-paste diff generator for TypeScript/Zod, Python/FastMCP, and Go
