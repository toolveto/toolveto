import * as fs from 'node:fs';
import * as path from 'node:path';

export interface InitOptions {
  ci?: string;
  output?: string;
  force?: boolean;
}

const GITHUB_ACTIONS_WORKFLOW = `name: ToolVeto MCP Reliability & Chaos Gate

on:
  pull_request:
    branches: [main, master]
  push:
    branches: [main, master]

concurrency:
  group: toolveto-\${{ github.ref }}
  cancel-in-progress: true

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  toolveto-gate:
    name: ToolVeto Deterministic MCP Audit
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Setup Node.js 22
        uses: actions/setup-node@v4
        with:
          node-version: 22

      - name: Run ToolVeto Deterministic Battery & Lockfile Gate
        env:
          TOOLVETO_TOKEN: \${{ secrets.TOOLVETO_LICENSE_KEY }}
        run: |
          npx --yes toolveto@latest check . --ephemeral-mock --threshold 80
          if [ -f "toolveto.lock.json" ]; then
            npx --yes toolveto@latest lock . --verify
          fi
`;

const GITLAB_CI_WORKFLOW = `# ToolVeto MCP Reliability & Chaos Gate (GitLab CI)
stages:
  - mcp-audit

toolveto_reliability_gate:
  stage: mcp-audit
  image: node:22-alpine
  timeout: 10 minutes
  interruptible: true
  script:
    - npx --yes toolveto@latest check . --ephemeral-mock --threshold 80
    - |
      if [ -f "toolveto.lock.json" ]; then
        npx --yes toolveto@latest lock . --verify
      fi
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
`;

export async function initCommand(targetDir = '.', options: InitOptions = {}): Promise<void> {
  const ciProvider = (options.ci || 'github-actions').toLowerCase();
  const baseDir = path.resolve(process.cwd(), targetDir);
  const relPath =
    options.output ||
    (ciProvider === 'gitlab' ? '.gitlab-ci.toolveto.yml' : '.github/workflows/toolveto.yml');
  const outPath = path.resolve(baseDir, relPath);

  if (fs.existsSync(outPath) && !options.force) {
    console.log(`\n✅ ToolVeto CI gate already exists at ${outPath} (use --force to overwrite).\n`);
    return;
  }

  const template = ciProvider === 'gitlab' ? GITLAB_CI_WORKFLOW : GITHUB_ACTIONS_WORKFLOW;
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, template, 'utf-8');
  console.log(`\n✅ Initialized ToolVeto ${ciProvider} gate at ${outPath}`);
  console.log(`   Next step: npx toolveto@latest lock . --output toolveto.lock.json\n`);
}
