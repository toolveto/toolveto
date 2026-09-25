# toolveto

CLI tool for deterministic chaos testing and auto-remediation of Model Context Protocol (MCP) servers.

```bash
# Run deterministic checks in CI (<90s, $0, zero LLM)
npx toolveto check ./my-mcp-server

# Auto-apply remediation AST patches to your source code
npx toolveto fix --apply
```
