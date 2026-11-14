# Acme FinTech MCP Server — ToolVeto Showcase Repository

This standalone repository demonstrates **ToolVeto** across the entire MCP lifecycle:

1. **Free PR GitHub Action Gate (`$0`, Zero LLM, Zero Data Egress)**:
   - Blocks double-charges (`VETO_IDEMP`), 500 stack-trace loops, and context bombs in PRs before merge.
   - Auto-remediates schemas in 1 command (`npx toolveto fix . --apply`) from **20/100 [Failed]** to **100/100 [Platinum]**.
   - Pins SHA-256 tool hashes (`toolveto.lock.json`) to block silent schema drift / rug-pulls.
2. **Live Running Streamable HTTP MCP Server (`:4010/mcp`) + `@toolveto/shield` Proxy (`:8080/mcp`)**:
   - Hot-switchable runtime states (`v1-vulnerable`, `v1-hardened`, `v2-drifted`) via `POST /admin/mode`.
   - Exposes `/stats` so you can prove upstream card charges stay at `1` during a 10x agent retry storm behind Shield.
3. **ToolVeto Team & Shield Cloud Governance**:
   - Sealed 60% Adversarial Honeytrap Corpus, RFC 7515 Detached JWS Attestation, PII-scrubbed Failure Lakehouse, and Admin Baseline Drift Promotion.

---

## Pushing to GitHub to Demo a Real Pull Request

You can push this directory as its own standalone GitHub repository in 30 seconds:

```bash
cp -R showcase/acme-fintech-mcp /tmp/acme-fintech-mcp-demo
cd /tmp/acme-fintech-mcp-demo
git init -b main
git add package.json server.mjs .github/workflows/toolveto-pr.yml README.md
git commit -m "chore: initial repo scaffold"

# Create a GitHub repo (via GitHub CLI) and push main
gh repo create acme-fintech-mcp-demo --private --source=. --push

# Open a vulnerable feature PR to watch ToolVeto block the merge!
git checkout -b feat/unsafe-card-charging
git add tools.json .cursor/mcp.json
git commit -m "feat: add card charging and transaction ledger tools"
git push -u origin feat/unsafe-card-charging
gh pr create --title "feat: add MCP card charging tools" --body "Adds payment mutation & ledger query tools."

# Now auto-fix the PR in 2 commands and watch the PR gate turn 100/100 Platinum!
npx toolveto@latest fix . --apply
npx toolveto@latest lock .
git add tools.json toolveto.lock.json
git commit -m "fix: enforce ToolVeto idempotency, dry-run, pagination & SHA-256 lockfile"
git push
```

## Running Locally via the Master Showcase Orchestrator

From the workspace root:

```bash
./scripts/showcase-e2e.sh verify-all      # Full automated 4-Act verification
./scripts/showcase-e2e.sh start           # Launch live MCP (:4010), Shield (:8080), Cloud API (:3001) & Web (:3000)
./scripts/showcase-e2e.sh act1-pr-gate    # Run Free PR Gate -> Auto-Fix -> 100/100 Platinum
./scripts/showcase-e2e.sh act2-paid-suite # Validate all Team & Shield paid checks on live MCP server
./scripts/showcase-e2e.sh act3-zero-egress# Mathematical Zero-Data-Egress & PII Redaction proof
./scripts/showcase-e2e.sh act4-baseline-drift # V1 Baseline -> V2 Drift Flagged -> Admin Promotes New Baseline
```
