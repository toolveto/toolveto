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

permissions:
  contents: read
  pull-requests: write

jobs:
  toolveto-gate:
    name: ToolVeto Deterministic MCP Audit
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Setup Node.js 22
        uses: actions/setup-node@v4
        with:
          node-version: 22

      - name: Run ToolVeto 27-Check Deterministic Battery
        env:
          TOOLVETO_TOKEN: \${{ secrets.TOOLVETO_LICENSE_KEY }}
        run: |
          npx --yes toolveto@latest check . --ephemeral-mock --threshold 80
          npx --yes toolveto@latest lock . --verify
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

  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, GITHUB_ACTIONS_WORKFLOW, 'utf-8');
  console.log(`\n✅ Initialized ToolVeto ${ciProvider} gate at ${outPath}`);
  console.log(`   Next step: npx toolveto@latest lock . --output toolveto.lock.json\n`);
}
