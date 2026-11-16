# toolveto

CLI tool for deterministic chaos testing and auto-remediation of Model Context Protocol (MCP) servers.

```bash
# Run 45 deterministic Free OSS checks across 18 invariant families (<90s, $0, zero LLM)
npx toolveto check ./my-mcp-server
npx toolveto doctor

# Auto-apply remediation AST patches to your source code
npx toolveto fix --apply
```
