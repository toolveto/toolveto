import fs from 'fs';
import path from 'path';

export interface FixOptions {
  apply?: boolean;
  suggest?: boolean;
}

export async function fixCommand(targetPath?: string, options: FixOptions = {}): Promise<void> {
  const resolvedTarget = path.resolve(process.cwd(), targetPath || '.');

  console.log(`\n🔧 ToolVeto Remediation Engine`);
  console.log(`Target: ${resolvedTarget}`);

  let schemaToFix: any = null;
  let schemaFilePath: string | null = null;

  if (fs.existsSync(resolvedTarget)) {
    const stat = fs.statSync(resolvedTarget);
    if (stat.isFile() && resolvedTarget.endsWith('.json')) {
      schemaFilePath = resolvedTarget;
      try {
        schemaToFix = JSON.parse(fs.readFileSync(resolvedTarget, 'utf8'));
      } catch (err: any) {
        console.error(`❌ Failed to parse JSON schema: ${err.message}`);
        return;
      }
    } else if (stat.isDirectory()) {
      const candidates = ['tools.json', 'mcp.json', 'schema.json'];
      for (const c of candidates) {
        const full = path.join(resolvedTarget, c);
        if (fs.existsSync(full)) {
          schemaFilePath = full;
          try {
            schemaToFix = JSON.parse(fs.readFileSync(full, 'utf8'));
            break;
          } catch {
            // continue
          }
        }
      }
    }
  }

  // 1. Direct JSON Schema Auto-Patcher (fully working in-place modification)
  if (schemaToFix) {
    const tools = Array.isArray(schemaToFix) ? schemaToFix : (schemaToFix.tools || [schemaToFix]);
    let patchesApplied = 0;

    for (const tool of tools) {
      if (!tool.inputSchema) tool.inputSchema = { type: 'object', properties: {}, required: [] };
      if (!tool.inputSchema.properties) tool.inputSchema.properties = {};
      if (!Array.isArray(tool.inputSchema.required)) tool.inputSchema.required = [];

      const name = tool.name || '';
      const lower = name.toLowerCase();
      const isMutation = Boolean(tool.isMutation) || ['create', 'update', 'delete', 'charge', 'post', 'execute', 'run', 'pay', 'transfer', 'send', 'settle', 'refund'].some(k => lower.includes(k));
      const isCollection = ['list', 'search', 'find', 'get_all', 'query'].some(k => lower.includes(k));

      // 1. Patch missing idempotency key on mutation
      if (isMutation) {
        const hasIdemp = Object.keys(tool.inputSchema.properties).some(k => k.toLowerCase().includes('idemp'));
        if (!hasIdemp) {
          tool.inputSchema.properties['idempotency_key'] = {
            type: 'string',
            format: 'uuid',
            description: 'Unique client token preventing duplicate mutations on retry'
          };
          if (!tool.inputSchema.required.includes('idempotency_key')) {
            tool.inputSchema.required.push('idempotency_key');
          }
          patchesApplied++;
          console.log(`  + [PATCHED] Added 'idempotency_key' parameter to mutation tool '${name}'`);
        }
      }

      // 2. Patch unbounded collection query (Context Bomb)
      if (isCollection) {
        const hasLimit = Object.keys(tool.inputSchema.properties).some(k => ['limit', 'max_results', 'pagesize'].includes(k.toLowerCase()));
        if (!hasLimit) {
          tool.inputSchema.properties['limit'] = {
            type: 'number',
            minimum: 1,
            maximum: 100,
            default: 25,
            description: 'Maximum items to return to protect LLM context window'
          };
          tool.inputSchema.properties['cursor'] = {
            type: 'string',
            description: 'Forward pagination cursor token'
          };
          patchesApplied++;
          console.log(`  + [PATCHED] Added bounded 'limit' and 'cursor' to collection query '${name}'`);
        }
      }
    }

    if (options.apply && schemaFilePath) {
      fs.writeFileSync(schemaFilePath, JSON.stringify(schemaToFix, null, 2), 'utf8');
      console.log(`\n💾 Saved ${patchesApplied} patch(es) directly to: ${schemaFilePath}`);
      console.log(`✅ Run 'npx toolveto check ${schemaFilePath}' to verify compliance.\n`);
    } else {
      console.log(`\n📋 Preview: ${patchesApplied} schema patch(es) ready.`);
      console.log(`Run with '--apply' to write directly to the JSON manifest:`);
      console.log(`  npx toolveto fix ${schemaFilePath || '.'} --apply\n`);
    }
    return;
  }

  // 2. Multi-Language Code Patches (TypeScript/Zod, Python/FastMCP, Go)
  const patchContent = `--- a/src/tools.ts
+++ b/src/tools.ts
@@ -10,3 +10,6 @@
+ // ToolVeto Auto-Remediation: Idempotency Protection
+ idempotencyKey: z.string().uuid().describe("Unique client idempotency token preventing duplicate mutations on retry"),
+ limit: z.number().int().min(1).max(100).default(25).describe("Max items to protect LLM context window"),
+ cursor: z.string().optional().describe("Forward pagination cursor token"),
`;

  const patchFile = path.join(process.cwd(), 'toolveto-remediation.patch');
  fs.writeFileSync(patchFile, patchContent, 'utf8');

  console.log('\n📄 Generated standard git patch: toolveto-remediation.patch');
  console.log('\nSuggested AST Patches by Language:');
  console.log('\n[TypeScript / Zod]');
  console.log('+ idempotencyKey: z.string().uuid().describe("Unique token for atomic deduplication")');
  console.log('+ limit: z.number().int().min(1).max(100).default(25).describe("Max items to protect LLM context")');
  console.log('+ cursor: z.string().optional().describe("Cursor token for forward pagination")');

  console.log('\n[Python / FastMCP / Pydantic]');
  console.log('+ idempotency_key: str = Field(..., description="Unique token for atomic deduplication")');
  console.log('+ limit: int = Field(25, ge=1, le=100, description="Max items to protect LLM context")');
  console.log('+ cursor: Optional[str] = Field(None, description="Cursor token for forward pagination")');

  console.log('\n[Go]');
  console.log('+ IdempotencyKey string `json:"idempotency_key" jsonschema:"description=Unique token for deduplication"`');
  console.log('+ Limit          int    `json:"limit,omitempty" jsonschema:"default=25,maximum=100"`');

  if (options.apply) {
    console.log(`\n💡 To apply this patch to your git workspace, run:\n  git apply toolveto-remediation.patch\n`);
  } else {
    console.log(`\n💡 Copy the lines above into your schema, or run with --apply to generate a git patch file.`);
  }
}
