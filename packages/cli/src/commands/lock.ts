import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import type { McpToolDefinition } from '@toolveto/core';
import { computeToolDefinitionHash, canonicalizeJson } from '@toolveto/shield';
import { discoverToolsFromTarget } from '../discovery.js';

export interface LockCommandOptions {
  output?: string;
  verify?: boolean;
  demo?: boolean;
  allowExec?: boolean;
  weaveproof?: boolean;
  syncCloud?: boolean;
  approveCloud?: boolean;
  repo?: string;
  apiUrl?: string;
  licenseKey?: string;
}

export interface ToolVetoLockfile {
  version: string;
  generatedAt: string;
  target: string;
  manifestHash: string;
  tools: Record<
    string,
    {
      sha256: string;
      descriptionLength: number;
      isMutation: boolean;
    }
  >;
}

const DEMO_LOCK_TOOLS: McpToolDefinition[] = [
  {
    name: 'create_payment',
    description: 'Creates a financial payment transaction with idempotency protection',
    isMutation: true,
    inputSchema: {
      type: 'object',
      properties: {
        amount: { type: 'number' },
        idempotency_key: { type: 'string' },
      },
      required: ['amount', 'idempotency_key'],
    },
  },
];

function resolveLockCloudAuth(options: LockCommandOptions): { apiUrl: string; token: string; repo: string } {
  let savedUrl = '';
  let savedToken = '';
  try {
    const cfgPath = path.join(process.env.HOME || os.homedir(), '.toolveto', 'config.json');
    if (fs.existsSync(cfgPath)) {
      const parsed = JSON.parse(fs.readFileSync(cfgPath, 'utf-8'));
      if (typeof parsed.apiUrl === 'string') savedUrl = parsed.apiUrl.trim();
      if (typeof parsed.token === 'string') savedToken = parsed.token.trim();
    }
  } catch {
    // Ignore unreadable config
  }

  const apiUrl = (
    options.apiUrl ||
    process.env.TOOLVETO_API_URL ||
    savedUrl ||
    'https://api.toolveto.ai'
  ).replace(/\/+$/, '');

  const token = (
    options.licenseKey ||
    process.env.TOOLVETO_LICENSE_KEY ||
    process.env.TOOLVETO_TOKEN ||
    savedToken ||
    ''
  ).trim();

  const repo = (
    options.repo ||
    process.env.TOOLVETO_REPO ||
    process.env.GITHUB_REPOSITORY ||
    `local/${path.basename(process.cwd())}`
  ).trim();

  return { apiUrl, token, repo };
}

async function runCloudBaselineSync(
  tools: McpToolDefinition[],
  options: LockCommandOptions
): Promise<boolean> {
  if (!options.syncCloud && !options.approveCloud) return true;
  const { apiUrl, token, repo } = resolveLockCloudAuth(options);
  if (!token) {
    console.error(
      '\n❌ Cloud baseline sync requires authentication (`--license-key`, `TOOLVETO_LICENSE_KEY`, or `toolveto login`).'
    );
    process.exitCode = 1;
    return false;
  }

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${token}`,
    'X-ToolVeto-Token': token,
    'X-ToolVeto-License': token,
  };

  if (options.approveCloud) {
    const res = await fetch(`${apiUrl}/api/v1/drift/approve`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ repo, tools }),
    });
    const body = (await res.json().catch(() => ({}))) as Record<string, any>;
    if (!res.ok || !body.approved) {
      console.error(`\n❌ Cloud baseline promotion failed (${res.status}): ${body.error || 'Unknown error'}`);
      process.exitCode = 1;
      return false;
    }
    console.log(`☁️  Promoted & Locked Cloud Baseline for '${repo}': ${body.baselineHash} [${body.status}]`);
    return true;
  }

  const res = await fetch(`${apiUrl}/api/v1/drift/check`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ repo, tools }),
  });
  const body = (await res.json().catch(() => ({}))) as Record<string, any>;
  if (!res.ok) {
    console.error(`\n❌ Cloud drift check failed (${res.status}): ${body.error || 'Unknown error'}`);
    process.exitCode = 1;
    return false;
  }
  if (body.drifted) {
    const added = Array.isArray(body.diff?.addedTools) ? body.diff.addedTools : [];
    const removed = Array.isArray(body.diff?.removedTools) ? body.diff.removedTools : [];
    const modified = Array.isArray(body.diff?.modifiedTools) ? body.diff.modifiedTools : [];
    console.error(`\n❌ CLOUD BASELINE DRIFT DETECTED for '${repo}'!`);
    console.error(`   Pinned Baseline: ${body.previousHash}`);
    console.error(`   Current Hash:    ${body.currentHash}`);
    if (added.length) console.error(`   + Added Tools:    ${added.join(', ')}`);
    if (removed.length) console.error(`   - Removed Tools:  ${removed.join(', ')}`);
    if (modified.length) console.error(`   ~ Modified Tools: ${modified.join(', ')}`);
    console.error(
      `   Admin Action: Approve in /dashboard?tab=drift or run \`toolveto lock ${options.repo ? `--repo ${repo} ` : ''}--approve-cloud\`\n`
    );
    process.exitCode = 1;
    return false;
  }

  console.log(`☁️  Cloud Baseline Verified for '${repo}': ${body.currentHash} (STABLE)`);
  return true;
}

function resolveLockfileOutputPath(explicitOutput: string | undefined, verifyMode: boolean): string {
  if (explicitOutput) {
    return path.resolve(process.cwd(), explicitOutput);
  }
  const primary = path.resolve(process.cwd(), 'toolveto.lock.json');
  if (verifyMode && !fs.existsSync(primary)) {
    const legacy = path.resolve(process.cwd(), 'toolveto.lock');
    if (fs.existsSync(legacy)) {
      return legacy;
    }
  }
  return primary;
}

export async function lockCommand(targetPath?: string, options: LockCommandOptions = {}): Promise<void> {
  const target = targetPath || '.';
  const lockfilePath = resolveLockfileOutputPath(options.output, Boolean(options.verify));

  let tools: McpToolDefinition[] = [];
  try {
    const discovered = await discoverToolsFromTarget(target, {
      demo: options.demo,
      allowExec: options.allowExec,
      demoFallbackTools: DEMO_LOCK_TOOLS,
      keepClientOpen: false,
    });
    tools = discovered.tools;
  } catch (err: any) {
    console.error(`\n❌ Error discovering tools at '${target}': ${err.message}`);
    process.exitCode = 1;
    return;
  }

  if (tools.length === 0) {
    console.error(`\n❌ Error: No tools discovered at '${target}' to lock.`);
    process.exitCode = 1;
    return;
  }

  const toolEntries: ToolVetoLockfile['tools'] = {};
  for (const tool of tools) {
    const sha256 = computeToolDefinitionHash(tool as any);
    toolEntries[tool.name] = {
      sha256,
      descriptionLength: (tool.description || '').length,
      isMutation: Boolean(tool.isMutation),
    };
  }

  const manifestHash =
    'sha256:' + crypto.createHash('sha256').update(canonicalizeJson(toolEntries)).digest('hex');

  if (options.verify) {
    if (!fs.existsSync(lockfilePath)) {
      console.error(`\n❌ Lockfile verification failed: '${lockfilePath}' does not exist.`);
      process.exitCode = 1;
      return;
    }

    const existingLock: ToolVetoLockfile = JSON.parse(fs.readFileSync(lockfilePath, 'utf-8'));
    const drifted: string[] = [];

    for (const [name, currentMeta] of Object.entries(toolEntries)) {
      const pinned = existingLock.tools?.[name];
      if (!pinned || pinned.sha256 !== currentMeta.sha256) {
        drifted.push(name);
      }
    }
    for (const pinnedName of Object.keys(existingLock.tools || {})) {
      if (!toolEntries[pinnedName]) {
        drifted.push(pinnedName);
      }
    }

    if (drifted.length > 0) {
      console.error(`\n❌ RUG-PULL / SCHEMA DRIFT DETECTED: [${drifted.join(', ')}] do not match ${path.basename(lockfilePath)}!`);
      process.exitCode = 1;
      return;
    }

    console.log(`\n✅ Lockfile verified: All ${Object.keys(toolEntries).length} tool definition(s) match ${path.basename(lockfilePath)} (${manifestHash}).\n`);
    await runCloudBaselineSync(tools, options);
    return;
  }

  const lockData: ToolVetoLockfile = {
    version: '1.0',
    generatedAt: new Date().toISOString(),
    target,
    manifestHash,
    tools: toolEntries,
  };

  fs.mkdirSync(path.dirname(lockfilePath), { recursive: true });
  fs.writeFileSync(lockfilePath, JSON.stringify(lockData, null, 2), 'utf-8');
  console.log(`\n🔒 Generated Rug-Pull Lockfile: ${lockfilePath}`);
  console.log(`   Pinned Tools:  ${Object.keys(toolEntries).length}`);
  console.log(`   Manifest Hash: ${manifestHash}`);
  await runCloudBaselineSync(tools, options);
  if (options.weaveproof || Object.values(toolEntries).some((t) => t.isMutation)) {
    console.log(
      `   🛡️  WeaveProof Enterprise Ready: Run \`weaveproof-cli genome import --from-toolveto ${path.basename(
        lockfilePath
      )}\` to enforce inline SHA-256 tool pinning, @clamp dollar ceilings, and PAT-27 L3/L4 wire equivalence.\n`
    );
  } else {
    console.log('');
  }
}
