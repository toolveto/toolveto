import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import type { McpToolDefinition } from '@toolveto/core';
import { computeToolDefinitionHash, canonicalizeJson } from '@toolveto/shield';

export interface LockCommandOptions {
  output?: string;
  verify?: boolean;
  demo?: boolean;
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

function loadToolsFromTarget(resolvedTarget: string, demo = false): McpToolDefinition[] {
  let tools: McpToolDefinition[] = [];
  if (fs.existsSync(resolvedTarget)) {
    const stat = fs.statSync(resolvedTarget);
    if (stat.isFile() && resolvedTarget.endsWith('.json')) {
      const parsed = JSON.parse(fs.readFileSync(resolvedTarget, 'utf-8'));
      tools = Array.isArray(parsed) ? parsed : parsed.tools || [];
    } else if (stat.isDirectory()) {
      for (const candidate of ['tools.json', 'mcp.json', 'schema.json']) {
        const full = path.join(resolvedTarget, candidate);
        if (fs.existsSync(full)) {
          const parsed = JSON.parse(fs.readFileSync(full, 'utf-8'));
          tools = Array.isArray(parsed) ? parsed : parsed.tools || [];
          break;
        }
      }
    }
  }

  if (tools.length === 0 && demo) {
    tools = [
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
  }
  return tools;
}

export async function lockCommand(targetPath?: string, options: LockCommandOptions = {}): Promise<void> {
  const resolvedTarget = path.resolve(process.cwd(), targetPath || '.');
  const lockfilePath = path.resolve(process.cwd(), options.output || 'toolveto.lock');
  const tools = loadToolsFromTarget(resolvedTarget, options.demo);

  if (tools.length === 0) {
    console.error(`\n❌ Error: No tools discovered at '${targetPath || '.'}' to lock.`);
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
    return;
  }

  const lockData: ToolVetoLockfile = {
    version: '1.0',
    generatedAt: new Date().toISOString(),
    target: targetPath || '.',
    manifestHash,
    tools: toolEntries,
  };

  fs.writeFileSync(lockfilePath, JSON.stringify(lockData, null, 2), 'utf-8');
  console.log(`\n🔒 Generated Rug-Pull Lockfile: ${lockfilePath}`);
  console.log(`   Pinned Tools:  ${Object.keys(toolEntries).length}`);
  console.log(`   Manifest Hash: ${manifestHash}\n`);
}
