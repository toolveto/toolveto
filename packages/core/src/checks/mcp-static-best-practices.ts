import {
  CheckResult,
  McpPromptDefinition,
  McpResourceTemplateDefinition,
  McpToolAnnotations,
  McpToolDefinition,
  StaticSourceFile,
} from '../types.js';

const DESTRUCTIVE_VERB_PATTERN =
  /(^|_)(delete|drop|destroy|purge|wipe|truncate|terminate|revoke|remove|erase)(_|$)/i;
const EXTERNAL_NETWORK_HINT_PATTERN =
  /\b(url|uri|webhook|callback|endpoint|slack|github|stripe|twilio|email|smtp|sms|fetch|crawl|http|https|external api|third[- ]party|remote server)\b/i;
const COLLECTION_TOOL_PATTERN =
  /(^|_)(list|search|find|query|export|scan|browse|filter|fetch_all|history|logs|messages|transactions|invoices)(_|$)/i;
const PAGINATION_PARAM_NAMES = new Set([
  'limit',
  'page_size',
  'pagesize',
  'per_page',
  'perpage',
  'max_results',
  'maxresults',
  'top',
  'take',
  'first',
  'count',
]);
const CONSTRAINED_STRING_PARAM_PATTERN =
  /(^|_)(email|url|uri|webhook|callback|date|uuid|currency|status|country|region|phone|filepath|file_path)(_|$)/i;
const BOUNDED_NUMBER_PARAM_PATTERN =
  /(^|_)(amount|price|fee|balance|quantity|qty|count|limit|page_size|port|timeout|max_items)(_|$)/i;
const INVISIBLE_OR_BIDI_PATTERN = /[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/;
const MIXED_SCRIPT_HOMOGLYPH_PATTERN = /(?=.*[A-Za-z])(?=.*[\u0400-\u04FF\u0370-\u03FF])/;
const SAFE_TOOL_NAME_PATTERN = /^[A-Za-z0-9_.:/-]+$/;
const DANGEROUS_EXEC_SQL_PARAM_PATTERN =
  /^(command|cmd|shell|bash|sh|exec|eval|code|script|raw_sql|sql|sql_query|query_raw)$/i;
const DANGEROUS_PATH_PARAM_PATTERN =
  /^(file_path|filepath|dir_path|directory|target_path|local_path|output_path)$/i;
const SENSITIVE_OUTPUT_KEY_PATTERN =
  /(^|_)(password|passwd|secret|private_key|api_key|apikey|access_token|refresh_token|auth_token|ssn|cvv|card_number)(_|$)/i;

/**
 * Resolves unified MCP 2025-03-26+ annotations from both flat tool fields and nested `tool.annotations`.
 */
export function resolveToolAnnotations(tool: McpToolDefinition): McpToolAnnotations {
  return {
    title: tool.annotations?.title,
    readOnlyHint: tool.readOnlyHint ?? tool.annotations?.readOnlyHint,
    destructiveHint: tool.destructiveHint ?? tool.annotations?.destructiveHint,
    idempotentHint: tool.idempotentHint ?? tool.annotations?.idempotentHint,
    openWorldHint: tool.openWorldHint ?? tool.annotations?.openWorldHint,
  };
}

/**
 * Normalizes a tool definition so flat annotation hints stay synchronized with nested `annotations`.
 */
export function normalizeToolAnnotations(tool: McpToolDefinition): McpToolDefinition {
  const resolved = resolveToolAnnotations(tool);
  return {
    ...tool,
    readOnlyHint: resolved.readOnlyHint,
    destructiveHint: resolved.destructiveHint,
    idempotentHint: resolved.idempotentHint,
    openWorldHint: resolved.openWorldHint,
  };
}

function stripCommentsAndStringsForStdoutScan(content: string, language: StaticSourceFile['language']): string[] {
  const lines = content.split(/\r?\n/);
  const matches: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const trimmed = line.trim();
    if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) continue;

    if (language === 'typescript' || language === 'javascript') {
      if (/\bconsole\.(log|info|debug|warn)\s*\(/.test(line)) {
        matches.push(`line ${i + 1}: ${trimmed.slice(0, 80)}`);
      }
    } else if (language === 'python') {
      if (/\bprint\s*\(/.test(line) && !/file\s*=\s*sys\.stderr/.test(line)) {
        matches.push(`line ${i + 1}: ${trimmed.slice(0, 80)}`);
      }
    } else if (language === 'go') {
      if (/\bfmt\.(Print|Println|Printf)\s*\(/.test(line)) {
        matches.push(`line ${i + 1}: ${trimmed.slice(0, 80)}`);
      }
    }
  }
  return matches;
}

/**
 * TC-STDIO-001 (D2): Detects stdout JSON-RPC frame corruption in stdio MCP servers.
 */
export function runStdioStdoutCheck(
  sourceFiles?: StaticSourceFile[],
  target?: string,
  transportMode?: string
): CheckResult {
  const start = Date.now();
  if (target && /^https?:\/\//i.test(target)) {
    return {
      checkId: 'TC-STDIO-001',
      dimension: 'D2',
      tool: '_transport',
      status: 'PASS',
      severity: 'INFO',
      description: 'Remote HTTP target detected — stdio stdout JSON-RPC frame check not applicable.',
      evidence: { evidenceQuality: 'STATIC-ONLY', details: { transport: 'http' } },
      durationMs: Date.now() - start,
    };
  }

  if (!sourceFiles || sourceFiles.length === 0) {
    return {
      checkId: 'TC-STDIO-001',
      dimension: 'D2',
      tool: '_transport',
      status: 'PASS',
      severity: 'INFO',
      description: 'No local source files supplied for stdio stdout frame audit.',
      evidence: { evidenceQuality: 'STATIC-ONLY', details: { filesScanned: 0 } },
      durationMs: Date.now() - start,
    };
  }

  const violations: Array<{ file: string; hits: string[] }> = [];
  for (const file of sourceFiles) {
    const usesStdio =
      /\bStdioServerTransport\b|transport\s*=\s*["']stdio["']|stdio_server|process\.stdin|sys\.stdin|os\.Stdin/i.test(
        file.content
      );
    const usesHttpServer =
      /\bStreamableHTTPServerTransport\b|\bhttp\.createServer\b|\bexpress\s*\(/i.test(file.content);

    // Pure HTTP servers (or HTTP listener entrypoints without StdioServerTransport) do not frame JSON-RPC over stdout
    if (!usesStdio && transportMode !== 'stdio') continue;
    if (usesHttpServer && !/\bStdioServerTransport\b/.test(file.content)) continue;

    const hits = stripCommentsAndStringsForStdoutScan(file.content, file.language);
    if (hits.length > 0) {
      violations.push({ file: file.path, hits: hits.slice(0, 5) });
    }
  }

  if (violations.length > 0) {
    return {
      checkId: 'TC-STDIO-001',
      dimension: 'D2',
      tool: '_transport',
      status: 'FAIL',
      severity: 'HIGH',
      description: `Stdio MCP stdout pollution detected in ${violations.length} file(s): writing console.log/print/fmt.Print corrupts JSON-RPC framing.`,
      evidence: {
        evidenceQuality: 'STATIC-ONLY',
        details: { violations, filesScanned: sourceFiles.length },
      },
      fix: {
        summary: 'Write diagnostic logs to stderr (`console.error` / `sys.stderr`) instead of stdout.',
        diffs: [
          {
            language: 'typescript-zod',
            code: `// Bad: console.log('Server started') corrupts stdio JSON-RPC stream\nconsole.error('Server started on stderr');`,
          },
          {
            language: 'python-fastmcp',
            code: `import sys\nprint('Server started', file=sys.stderr)`,
          },
        ],
      },
      durationMs: Date.now() - start,
    };
  }

  return {
    checkId: 'TC-STDIO-001',
    dimension: 'D2',
    tool: '_transport',
    status: 'PASS',
    severity: 'INFO',
    description: 'Stdio JSON-RPC transport is free of raw console.log/print stdout frame corruption.',
    evidence: { evidenceQuality: 'STATIC-ONLY', details: { filesScanned: sourceFiles.length } },
    durationMs: Date.now() - start,
  };
}

/**
 * TC-ANNOTATION-002 (D4): Validates destructiveHint and openWorldHint annotation consistency.
 */
export function runDestructiveOpenWorldAnnotationCheck(tool: McpToolDefinition): CheckResult {
  const start = Date.now();
  const hints = resolveToolAnnotations(tool);
  const props = tool.inputSchema?.properties || {};
  const propKeys = Object.keys(props);
  const isDestructiveByName = DESTRUCTIVE_VERB_PATTERN.test(tool.name);
  const isNetworkTool =
    EXTERNAL_NETWORK_HINT_PATTERN.test(tool.name) ||
    EXTERNAL_NETWORK_HINT_PATTERN.test(tool.description || '') ||
    propKeys.some((k) => EXTERNAL_NETWORK_HINT_PATTERN.test(k) || props[k]?.format === 'uri');

  if (hints.readOnlyHint === true && hints.destructiveHint === true) {
    return {
      checkId: 'TC-ANNOTATION-002',
      dimension: 'D4',
      tool: tool.name,
      status: 'FAIL',
      severity: 'HIGH',
      description: `Contradictory MCP annotations on '${tool.name}': readOnlyHint=true cannot coexist with destructiveHint=true.`,
      evidence: { evidenceQuality: 'STATIC-ONLY', details: { hints } },
      fix: {
        summary: 'Set readOnlyHint and destructiveHint consistently with actual side effects.',
        diffs: [
          {
            language: 'typescript-zod',
            code: `annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false }`,
          },
        ],
      },
      durationMs: Date.now() - start,
    };
  }

  if (hints.destructiveHint === false && isDestructiveByName) {
    return {
      checkId: 'TC-ANNOTATION-002',
      dimension: 'D4',
      tool: tool.name,
      status: 'FAIL',
      severity: 'HIGH',
      description: `Misleading destructiveHint=false on destructive tool '${tool.name}' — clients may bypass confirmation prompts.`,
      evidence: { evidenceQuality: 'STATIC-ONLY', details: { hints, matchedDestructiveVerb: true } },
      fix: {
        summary: 'Set destructiveHint: true so host applications prompt users before irreversible actions.',
        diffs: [
          {
            language: 'typescript-zod',
            code: `annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: ${Boolean(isNetworkTool)} }`,
          },
        ],
      },
      durationMs: Date.now() - start,
    };
  }

  if (hints.openWorldHint === false && isNetworkTool) {
    return {
      checkId: 'TC-ANNOTATION-002',
      dimension: 'D4',
      tool: tool.name,
      status: 'FAIL',
      severity: 'HIGH',
      description: `Contradictory openWorldHint=false on '${tool.name}' which references external URLs/webhooks/APIs.`,
      evidence: { evidenceQuality: 'STATIC-ONLY', details: { hints, isNetworkTool: true } },
      fix: {
        summary: 'Set openWorldHint: true for tools interacting with external entities or URLs.',
        diffs: [
          {
            language: 'typescript-zod',
            code: `annotations: { openWorldHint: true }`,
          },
        ],
      },
      durationMs: Date.now() - start,
    };
  }

  const hasAnyAnnotation =
    hints.readOnlyHint !== undefined ||
    hints.destructiveHint !== undefined ||
    hints.idempotentHint !== undefined ||
    hints.openWorldHint !== undefined;

  if (!hasAnyAnnotation || (isDestructiveByName && hints.destructiveHint === undefined) || (isNetworkTool && hints.openWorldHint === undefined)) {
    return {
      checkId: 'TC-ANNOTATION-002',
      dimension: 'D4',
      tool: tool.name,
      status: 'WARN',
      severity: isDestructiveByName || isNetworkTool ? 'MEDIUM' : 'LOW',
      description: `Tool '${tool.name}' omits recommended MCP annotation hints (destructiveHint / openWorldHint / readOnlyHint).`,
      evidence: { evidenceQuality: 'STATIC-ONLY', details: { hints, isDestructiveByName, isNetworkTool } },
      fix: {
        summary: 'Declare explicit MCP tool annotations for host permission prompts and safety gating.',
        diffs: [
          {
            language: 'typescript-zod',
            code: `annotations: {\n  readOnlyHint: ${!tool.isMutation && !isDestructiveByName},\n  destructiveHint: ${isDestructiveByName},\n  openWorldHint: ${isNetworkTool},\n}`,
          },
        ],
      },
      durationMs: Date.now() - start,
    };
  }

  return {
    checkId: 'TC-ANNOTATION-002',
    dimension: 'D4',
    tool: tool.name,
    status: 'PASS',
    severity: 'INFO',
    description: `MCP destructiveHint and openWorldHint annotations on '${tool.name}' are consistent.`,
    evidence: { evidenceQuality: 'STATIC-ONLY', details: { hints } },
    durationMs: Date.now() - start,
  };
}

function collectArrayBounds(schema: any, pathPrefix = '', visited = new WeakSet<object>()): Array<{ path: string; maxItems?: number }> {
  if (!schema || typeof schema !== 'object') return [];
  if (visited.has(schema)) return [];
  visited.add(schema);

  const out: Array<{ path: string; maxItems?: number }> = [];
  if (schema.type === 'array') {
    out.push({ path: pathPrefix || 'root', maxItems: typeof schema.maxItems === 'number' ? schema.maxItems : undefined });
  }
  if (schema.properties && typeof schema.properties === 'object') {
    for (const [k, v] of Object.entries(schema.properties)) {
      out.push(...collectArrayBounds(v, pathPrefix ? `${pathPrefix}.${k}` : k, visited));
    }
  }
  if (schema.items && typeof schema.items === 'object') {
    out.push(...collectArrayBounds(schema.items, `${pathPrefix}[]`, visited));
  }
  return out;
}

/**
 * TC-SCHEMA-004 (D3): Enforces bounded pagination limits and maxItems on arrays to prevent context floods.
 */
export function runPaginationArrayBoundCheck(tool: McpToolDefinition): CheckResult {
  const start = Date.now();
  const props = tool.inputSchema?.properties || {};
  const arrayFields = collectArrayBounds(tool.inputSchema);
  const excessiveArrays = arrayFields.filter((f) => typeof f.maxItems === 'number' && f.maxItems > 1000);
  const unboundedArrays = arrayFields.filter((f) => f.maxItems === undefined);

  const pageParamEntry = Object.entries(props).find(([k]) => PAGINATION_PARAM_NAMES.has(k.toLowerCase()));
  const pageMax = pageParamEntry && typeof (pageParamEntry[1] as any)?.maximum === 'number' ? (pageParamEntry[1] as any).maximum : undefined;
  const pageEnum = pageParamEntry && Array.isArray((pageParamEntry[1] as any)?.enum);
  const isCollectionTool = COLLECTION_TOOL_PATTERN.test(tool.name) && !/^get_[a-z0-9_]+$/i.test(tool.name);

  if (excessiveArrays.length > 0 || (pageMax !== undefined && pageMax > 1000)) {
    return {
      checkId: 'TC-SCHEMA-004',
      dimension: 'D3',
      tool: tool.name,
      status: 'FAIL',
      severity: 'HIGH',
      description: `Schema bound on '${tool.name}' permits >1000 elements/rows in a single call, risking LLM context overflow.`,
      evidence: { evidenceQuality: 'STATIC-ONLY', details: { excessiveArrays, pageMax } },
      fix: {
        summary: 'Cap pagination limit (`maximum: 100`) and array parameters (`maxItems: 100`).',
        diffs: [
          {
            language: 'json-schema',
            code: `{ "limit": { "type": "integer", "minimum": 1, "maximum": 100 }, "items": { "type": "array", "maxItems": 100 } }`,
          },
        ],
      },
      durationMs: Date.now() - start,
    };
  }

  if (unboundedArrays.length > 0 || (isCollectionTool && (!pageParamEntry || (pageMax === undefined && !pageEnum)))) {
    return {
      checkId: 'TC-SCHEMA-004',
      dimension: 'D3',
      tool: tool.name,
      status: 'WARN',
      severity: 'MEDIUM',
      description: `Tool '${tool.name}' lacks explicit schema bounds (${unboundedArrays.length > 0 ? 'array maxItems' : 'limit.maximum / enum'}).`,
      evidence: {
        evidenceQuality: 'STATIC-ONLY',
        details: { unboundedArrays: unboundedArrays.map((a) => a.path), isCollectionTool, hasPageParam: Boolean(pageParamEntry) },
      },
      fix: {
        summary: 'Add JSON Schema `maximum` on pagination limits and `maxItems` on array inputs.',
        diffs: [
          {
            language: 'json-schema',
            code: `{ "limit": { "type": "integer", "minimum": 1, "maximum": 100 }, "cursor": { "type": "string" } }`,
          },
        ],
      },
      durationMs: Date.now() - start,
    };
  }

  return {
    checkId: 'TC-SCHEMA-004',
    dimension: 'D3',
    tool: tool.name,
    status: 'PASS',
    severity: 'INFO',
    description: `Pagination and array bounds on '${tool.name}' are properly constrained.`,
    evidence: { evidenceQuality: 'STATIC-ONLY', details: { arrayFieldCount: arrayFields.length, pageMax } },
    durationMs: Date.now() - start,
  };
}

/**
 * TC-SCHEMA-005 (D3): Checks semantic parameter constraints (min/max/format/pattern/enum).
 */
export function runParamConstraintsCheck(tool: McpToolDefinition): CheckResult {
  const start = Date.now();
  const props = tool.inputSchema?.properties || {};
  const invalidRanges: string[] = [];
  const unconstrained: string[] = [];

  for (const [key, rawSchema] of Object.entries(props)) {
    const s: any = rawSchema || {};
    if (typeof s.minimum === 'number' && typeof s.maximum === 'number' && s.minimum > s.maximum) {
      invalidRanges.push(`${key} (minimum ${s.minimum} > maximum ${s.maximum})`);
    }
    if (typeof s.minLength === 'number' && typeof s.maxLength === 'number' && s.minLength > s.maxLength) {
      invalidRanges.push(`${key} (minLength ${s.minLength} > maxLength ${s.maxLength})`);
    }
    if (typeof s.minItems === 'number' && typeof s.maxItems === 'number' && s.minItems > s.maxItems) {
      invalidRanges.push(`${key} (minItems ${s.minItems} > maxItems ${s.maxItems})`);
    }

    if (s.type === 'string' && CONSTRAINED_STRING_PARAM_PATTERN.test(key)) {
      if (!s.format && !s.pattern && !Array.isArray(s.enum) && s.minLength === undefined && s.maxLength === undefined) {
        unconstrained.push(key);
      }
    } else if ((s.type === 'number' || s.type === 'integer') && BOUNDED_NUMBER_PARAM_PATTERN.test(key)) {
      if (
        s.minimum === undefined &&
        s.exclusiveMinimum === undefined &&
        s.maximum === undefined &&
        s.exclusiveMaximum === undefined &&
        !Array.isArray(s.enum)
      ) {
        unconstrained.push(key);
      }
    }
  }

  if (invalidRanges.length > 0) {
    return {
      checkId: 'TC-SCHEMA-005',
      dimension: 'D3',
      tool: tool.name,
      status: 'FAIL',
      severity: 'HIGH',
      description: `Unsatisfiable JSON Schema range bounds on '${tool.name}': ${invalidRanges.join(', ')}.`,
      evidence: { evidenceQuality: 'STATIC-ONLY', details: { invalidRanges } },
      durationMs: Date.now() - start,
    };
  }

  if (unconstrained.length >= 4) {
    return {
      checkId: 'TC-SCHEMA-005',
      dimension: 'D3',
      tool: tool.name,
      status: 'FAIL',
      severity: 'MEDIUM',
      description: `Tool '${tool.name}' leaves ${unconstrained.length} domain/numeric parameters unconstrained (${unconstrained.join(', ')}).`,
      evidence: { evidenceQuality: 'STATIC-ONLY', details: { unconstrained } },
      fix: {
        summary: 'Add `format`, `pattern`, `enum`, `minimum`, or `maximum` constraints to prevent LLM hallucinations.',
        diffs: [
          {
            language: 'typescript-zod',
            code: `z.object({ amount: z.number().positive(), date: z.string().date(), currency: z.enum(['USD', 'EUR', 'GBP']) })`,
          },
        ],
      },
      durationMs: Date.now() - start,
    };
  }

  if (unconstrained.length > 0) {
    return {
      checkId: 'TC-SCHEMA-005',
      dimension: 'D3',
      tool: tool.name,
      status: 'WARN',
      severity: 'LOW',
      description: `Domain/numeric parameter(s) [${unconstrained.join(', ')}] on '${tool.name}' lack explicit min/max/format/enum constraints.`,
      evidence: { evidenceQuality: 'STATIC-ONLY', details: { unconstrained } },
      fix: {
        summary: 'Constrain string formats and positive numeric ranges in JSON Schema / Zod.',
        diffs: [
          {
            language: 'json-schema',
            code: `{ "${unconstrained[0]}": { "type": "string", "pattern": "^[a-zA-Z0-9_-]{3,64}$" } }`,
          },
        ],
      },
      durationMs: Date.now() - start,
    };
  }

  return {
    checkId: 'TC-SCHEMA-005',
    dimension: 'D3',
    tool: tool.name,
    status: 'PASS',
    severity: 'INFO',
    description: `Parameter domain and numeric bounds on '${tool.name}' are properly constrained.`,
    evidence: { evidenceQuality: 'STATIC-ONLY', details: { propertyCount: Object.keys(props).length } },
    durationMs: Date.now() - start,
  };
}

/**
 * TC-CTX-002 (D3): Detects toolset bloat (>40 tools) and unpinned dynamic tool registration (`listChanged` rug-pull).
 */
export function runToolRugPullBloatCheck(
  tools: McpToolDefinition[],
  sourceFiles?: StaticSourceFile[]
): CheckResult {
  const start = Date.now();
  const bloatedTools: string[] = [];
  let maxChars = 0;

  for (const t of tools) {
    const serializedLen = JSON.stringify({ name: t.name, description: t.description || '', inputSchema: t.inputSchema }).length;
    if (serializedLen > maxChars) maxChars = serializedLen;
    if (serializedLen > 8000) bloatedTools.push(`${t.name} (${serializedLen} chars)`);
  }

  const rugPullSignals: string[] = [];
  let hasUnsafeDynamicRegistration = false;
  if (sourceFiles) {
    for (const file of sourceFiles) {
      if (/\bsendToolListChanged\b|notifications\/tools\/list_changed|\blistChanged\s*:\s*true\b/.test(file.content)) {
        rugPullSignals.push(file.path);
        if (/\bfetch\s*\(|axios|requests\.(get|post)|eval\s*\(/i.test(file.content)) {
          hasUnsafeDynamicRegistration = true;
        }
      }
    }
  }

  if (tools.length > 80 || bloatedTools.length > 0 || hasUnsafeDynamicRegistration) {
    return {
      checkId: 'TC-CTX-002',
      dimension: 'D3',
      tool: '_suite',
      status: 'FAIL',
      severity: 'HIGH',
      vetoClass: hasUnsafeDynamicRegistration ? 'VETO_INJECT' : undefined,
      description: hasUnsafeDynamicRegistration
        ? `Dynamic remote tool registration / listChanged rug-pull risk detected in ${rugPullSignals.join(', ')}.`
        : `Extreme MCP context bloat: ${tools.length} tools registered (max definition ${maxChars} chars).`,
      evidence: {
        evidenceQuality: 'STATIC-ONLY',
        details: { toolCount: tools.length, maxChars, bloatedTools, rugPullSignals, hasUnsafeDynamicRegistration },
      },
      fix: {
        summary: 'Keep exposed server toolsets focused (<=40 tools) and pin tool hashes via `toolveto lock` before deployment.',
        diffs: [
          {
            language: 'typescript-zod',
            code: `// Disable unpinned dynamic listChanged or gate mutations behind hash-verified allowlists\ncapabilities: { tools: { listChanged: false } }`,
          },
        ],
      },
      durationMs: Date.now() - start,
    };
  }

  if (tools.length > 40 || maxChars > 4000 || rugPullSignals.length > 0) {
    return {
      checkId: 'TC-CTX-002',
      dimension: 'D3',
      tool: '_suite',
      status: 'WARN',
      severity: 'MEDIUM',
      description: `Toolset hygiene warning: ${tools.length} tools, max def ${maxChars} chars, dynamic listChanged files=${rugPullSignals.length}.`,
      evidence: { evidenceQuality: 'STATIC-ONLY', details: { toolCount: tools.length, maxChars, rugPullSignals } },
      durationMs: Date.now() - start,
    };
  }

  return {
    checkId: 'TC-CTX-002',
    dimension: 'D3',
    tool: '_suite',
    status: 'PASS',
    severity: 'INFO',
    description: `Toolset count (${tools.length}) and static registration integrity are within safe context limits.`,
    evidence: { evidenceQuality: 'STATIC-ONLY', details: { toolCount: tools.length, maxChars } },
    durationMs: Date.now() - start,
  };
}

function isCatchAllRegexPattern(pattern: string): boolean {
  const trimmed = pattern.trim();
  if (!trimmed) return true;
  return /^(?:\^)?(?:\.\*|\.\+|\(\.\*\)|\(\.\+\)|\[\\s\\S\]\*|\[\\s\\S\]\+|\[\\w\\W\]\*|\[\^\]\*)(?:\$)?$/.test(trimmed);
}

function hasMeaningfulAllowlistConstraint(s: any): boolean {
  if (!s || typeof s !== 'object') return false;
  if (s.const !== undefined) return true;
  if (Array.isArray(s.enum) && s.enum.length > 0) return true;
  if (typeof s.pattern === 'string' && !isCatchAllRegexPattern(s.pattern)) return true;
  return false;
}

const BENIGN_CODE_SUFFIX_RE =
  /^(?:currency|status|postal|country|zip|area|error|promo|discount|invite|auth|verification|totp|mfa|lang|language|color|airport|iata|icao|mcc|sic|naics|hs|tax|reason|response|http|exit|return)_code$/i;
const EXPANDED_EXEC_SQL_PARAM_RE =
  /(?:^|_)(?:command|cmd|shell|bash|zsh|powershell|sh|exec|eval|code|script|raw_sql|sql|sql_query|query_raw)(?:_|$)/i;
const EXPANDED_PATH_PARAM_RE =
  /(?:^|_)(?:file_path|filepath|dir_path|directory|target_path|local_path|output_path)(?:_|$)/i;

function collectNestedParameters(
  schema: any,
  out: Array<{ name: string; schema: any }> = [],
  visited = new WeakSet<object>(),
  depth = 0
): Array<{ name: string; schema: any }> {
  if (!schema || typeof schema !== 'object' || depth > 16) return out;
  if (visited.has(schema)) return out;
  visited.add(schema);

  if (schema.properties && typeof schema.properties === 'object') {
    for (const [key, propSchema] of Object.entries(schema.properties)) {
      out.push({ name: key, schema: propSchema });
      collectNestedParameters(propSchema, out, visited, depth + 1);
    }
  }
  if (schema.items && typeof schema.items === 'object') {
    collectNestedParameters(schema.items, out, visited, depth + 1);
  }
  for (const branchKey of ['anyOf', 'oneOf', 'allOf'] as const) {
    if (Array.isArray(schema[branchKey])) {
      for (const sub of schema[branchKey]) {
        collectNestedParameters(sub, out, visited, depth + 1);
      }
    }
  }
  return out;
}

function isStringAcceptingSchema(s: any): boolean {
  if (!s || typeof s !== 'object') return true;
  if (s.type === undefined || s.type === 'string') return true;
  if (Array.isArray(s.type) && s.type.includes('string')) return true;
  if (s.type === 'array' && (!s.items || s.items.type === undefined || s.items.type === 'string')) return true;
  return false;
}

/**
 * TC-SEC-004 (D2): Audits tool/param names for Unicode homoglyphs/control chars, unsanitized command/SQL sinks, and prompt overrides.
 */
export function runParamNameAndSinkSecurityCheck(
  tool: McpToolDefinition,
  prompts?: McpPromptDefinition[]
): CheckResult {
  const start = Date.now();
  const nestedParams = collectNestedParameters(tool.inputSchema);
  const identifiers = [tool.name, ...nestedParams.map((p) => p.name)];

  for (const id of identifiers) {
    if (
      INVISIBLE_OR_BIDI_PATTERN.test(id) ||
      /[\uFF00-\uFFEF]/.test(id) ||
      MIXED_SCRIPT_HOMOGLYPH_PATTERN.test(id) ||
      !SAFE_TOOL_NAME_PATTERN.test(id)
    ) {
      return {
        checkId: 'TC-SEC-004',
        dimension: 'D2',
        tool: tool.name,
        status: 'FAIL',
        severity: 'CRITICAL',
        vetoClass: 'VETO_INJECT',
        description: `VETO_INJECT: Confusable Unicode homoglyph, zero-width control character, or unsafe identifier '${id}' on '${tool.name}'.`,
        evidence: { evidenceQuality: 'STATIC-ONLY', details: { suspiciousIdentifier: id } },
        durationMs: Date.now() - start,
      };
    }
  }

  if (prompts && prompts.length > 0) {
    for (const p of prompts) {
      const rawText = `${p.name} ${p.description || ''} ${p.templateText || ''}`;
      const normalizedText = rawText
        .normalize('NFKC')
        .replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/g, '');
      if (
        INVISIBLE_OR_BIDI_PATTERN.test(rawText) ||
        /(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|prompts|rules|directives)|system\s*override|<system>|<<SYS>>|you\s+are\s+now\s+(?:DAN|unfiltered|jailbroken)/i.test(
          normalizedText
        )
      ) {
        return {
          checkId: 'TC-SEC-004',
          dimension: 'D2',
          tool: tool.name,
          status: 'FAIL',
          severity: 'CRITICAL',
          vetoClass: 'VETO_INJECT',
          description: `VETO_INJECT: MCP prompt definition '${p.name}' contains hidden control/override instructions.`,
          evidence: { evidenceQuality: 'STATIC-ONLY', details: { promptName: p.name } },
          durationMs: Date.now() - start,
        };
      }
    }
  }

  const execSqlSinks: string[] = [];
  const pathSinks: string[] = [];
  for (const { name: key, schema: rawSchema } of nestedParams) {
    const s: any = rawSchema || {};
    if (!isStringAcceptingSchema(s)) continue;
    const hasConstraint = hasMeaningfulAllowlistConstraint(s);
    const isExecSqlName =
      DANGEROUS_EXEC_SQL_PARAM_PATTERN.test(key) ||
      (EXPANDED_EXEC_SQL_PARAM_RE.test(key) && !BENIGN_CODE_SUFFIX_RE.test(key));

    if (isExecSqlName && !hasConstraint) {
      execSqlSinks.push(key);
    } else if ((DANGEROUS_PATH_PARAM_PATTERN.test(key) || EXPANDED_PATH_PARAM_RE.test(key)) && !hasConstraint) {
      pathSinks.push(key);
    }
  }

  if (execSqlSinks.length > 0) {
    return {
      checkId: 'TC-SEC-004',
      dimension: 'D2',
      tool: tool.name,
      status: 'FAIL',
      severity: 'HIGH',
      description: `Tool '${tool.name}' exposes unconstrained command/code/SQL string sink(s) [${execSqlSinks.join(', ')}] without enum/pattern allowlist.`,
      evidence: { evidenceQuality: 'STATIC-ONLY', details: { execSqlSinks } },
      fix: {
        summary: 'Replace arbitrary shell/SQL strings with parameterized enums or structured action parameters.',
        diffs: [
          {
            language: 'typescript-zod',
            code: `action: z.enum(['status', 'restart', 'logs']) // instead of arbitrary command strings`,
          },
        ],
      },
      durationMs: Date.now() - start,
    };
  }

  if (pathSinks.length > 0) {
    return {
      checkId: 'TC-SEC-004',
      dimension: 'D2',
      tool: tool.name,
      status: 'WARN',
      severity: 'MEDIUM',
      description: `Tool '${tool.name}' accepts unconstrained filesystem path parameter(s) [${pathSinks.join(', ')}] without pattern or workspace restriction.`,
      evidence: { evidenceQuality: 'STATIC-ONLY', details: { pathSinks } },
      durationMs: Date.now() - start,
    };
  }

  return {
    checkId: 'TC-SEC-004',
    dimension: 'D2',
    tool: tool.name,
    status: 'PASS',
    severity: 'INFO',
    description: `Tool/parameter identifiers and input sink constraints on '${tool.name}' pass injection hygiene.`,
    evidence: { evidenceQuality: 'STATIC-ONLY', details: { identifiersChecked: identifiers.length } },
    durationMs: Date.now() - start,
  };
}

/**
 * TC-HTTP-001 (D2): Audits MCP HTTP/SSE transports for Origin checks, bind scope, query tokens, and plaintext remote URLs.
 */
export function runHttpTransportAuthCheck(
  sourceFiles?: StaticSourceFile[],
  target?: string
): CheckResult {
  const start = Date.now();
  if (target && /^http:\/\//i.test(target) && !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])([:/]|$)/i.test(target)) {
    return {
      checkId: 'TC-HTTP-001',
      dimension: 'D2',
      tool: '_transport',
      status: 'FAIL',
      severity: 'HIGH',
      description: `Plaintext non-loopback HTTP MCP endpoint detected ('${target}'); enforce HTTPS/TLS to prevent token interception.`,
      evidence: { evidenceQuality: 'STATIC-ONLY', details: { target } },
      durationMs: Date.now() - start,
    };
  }

  if (!sourceFiles || sourceFiles.length === 0) {
    return {
      checkId: 'TC-HTTP-001',
      dimension: 'D2',
      tool: '_transport',
      status: 'PASS',
      severity: 'INFO',
      description: 'No local HTTP/SSE transport source issues detected.',
      evidence: { evidenceQuality: 'STATIC-ONLY', details: { filesScanned: 0 } },
      durationMs: Date.now() - start,
    };
  }

  const queryTokenFiles: string[] = [];
  const publicNoAuthFiles: string[] = [];
  const legacySseFiles: string[] = [];
  const missingOriginLoopbackFiles: string[] = [];

  for (const file of sourceFiles) {
    const isHttpFile =
      /\bStreamableHTTPServerTransport\b|\bSSEServerTransport\b|\bhttp\.createServer\b|\bfastmcp\b|app\.(get|post)\s*\(\s*['"`]\/(mcp|sse)/i.test(
        file.content
      );
    if (!isHttpFile) continue;

    if (/(searchParams\.get|req\.query)\s*[\[(]\s*['"`](token|api_key|apikey|access_token|secret|auth)['"`]/i.test(file.content)) {
      queryTokenFiles.push(file.path);
    }

    const bindsAllInterfaces = /['"`](0\.0\.0\.0|::)['"`]/.test(file.content);
    const hasAuthCheck = /\b(authorization|bearer|requireAuth|x-api-key|jwt|oauth|verifyToken)\b/i.test(file.content);
    const hasOriginCheck = /\bheaders\.origin\b|\ballowedOrigins\b|\bcors\s*\(/i.test(file.content);

    if (bindsAllInterfaces && !hasAuthCheck) {
      publicNoAuthFiles.push(file.path);
    } else if (!bindsAllInterfaces && !hasOriginCheck && /\b(http\.createServer|StreamableHTTPServerTransport|SSEServerTransport)\b/.test(file.content)) {
      missingOriginLoopbackFiles.push(file.path);
    }

    if (/\bSSEServerTransport\b/.test(file.content) && !/\bStreamableHTTPServerTransport\b/.test(file.content)) {
      legacySseFiles.push(file.path);
    }
  }

  if (queryTokenFiles.length > 0) {
    return {
      checkId: 'TC-HTTP-001',
      dimension: 'D2',
      tool: '_transport',
      status: 'FAIL',
      severity: 'CRITICAL',
      vetoClass: 'VETO_EXFIL',
      description: `VETO_EXFIL: HTTP MCP server reads authentication token/secret from URL query string in ${queryTokenFiles.join(', ')}.`,
      evidence: { evidenceQuality: 'STATIC-ONLY', details: { queryTokenFiles } },
      fix: {
        summary: 'Read bearer credentials from `Authorization` header rather than URL query parameters.',
        diffs: [
          {
            language: 'typescript-zod',
            code: `const authHeader = req.headers.authorization?.replace(/^Bearer\\s+/i, '');`,
          },
        ],
      },
      durationMs: Date.now() - start,
    };
  }

  if (publicNoAuthFiles.length > 0) {
    return {
      checkId: 'TC-HTTP-001',
      dimension: 'D2',
      tool: '_transport',
      status: 'FAIL',
      severity: 'HIGH',
      description: `HTTP MCP server binds 0.0.0.0 without authentication verification in ${publicNoAuthFiles.join(', ')}.`,
      evidence: { evidenceQuality: 'STATIC-ONLY', details: { publicNoAuthFiles } },
      durationMs: Date.now() - start,
    };
  }

  if (legacySseFiles.length > 0 || missingOriginLoopbackFiles.length > 0) {
    return {
      checkId: 'TC-HTTP-001',
      dimension: 'D2',
      tool: '_transport',
      status: 'WARN',
      severity: 'MEDIUM',
      description: `HTTP transport hardening recommendation: ${
        legacySseFiles.length > 0 ? `legacy SSEServerTransport in ${legacySseFiles.join(', ')}` : `missing Origin header check in ${missingOriginLoopbackFiles.join(', ')}`
      }.`,
      evidence: { evidenceQuality: 'STATIC-ONLY', details: { legacySseFiles, missingOriginLoopbackFiles } },
      fix: {
        summary: 'Validate `req.headers.origin` against an explicit localhost/domain allowlist to prevent DNS rebinding.',
        diffs: [
          {
            language: 'typescript-zod',
            code: `const origin = req.headers.origin;\nif (origin && !/^https?:\\/\\/(localhost|127\\.0\\.0\\.1)(:\\d+)?$/.test(origin)) {\n  res.writeHead(403).end('Forbidden Origin'); return;\n}`,
          },
        ],
      },
      durationMs: Date.now() - start,
    };
  }

  return {
    checkId: 'TC-HTTP-001',
    dimension: 'D2',
    tool: '_transport',
    status: 'PASS',
    severity: 'INFO',
    description: 'HTTP/SSE MCP transport configuration passes Origin, bind-scope, and credential hygiene checks.',
    evidence: { evidenceQuality: 'STATIC-ONLY', details: { filesScanned: sourceFiles.length } },
    durationMs: Date.now() - start,
  };
}

function stripSourceComments(content: string): string {
  return content
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/^\s*\/\/.*$/gm, ' ')
    .replace(/^\s*#.*$/gm, ' ');
}

function fileHasRealPathContainmentGuard(content: string): boolean {
  const clean = stripSourceComments(content);
  const hasCanonicalize =
    /\b(?:path\.resolve|fs\.realpath|fs\.realpathSync|realpath|os\.path\.realpath|os\.path\.abspath|\.resolve\s*\(|filepath\.Clean|filepath\.EvalSymlinks)\b/.test(
      clean
    );
  const hasContainmentCheck =
    /\b(?:startsWith|path\.relative|commonpath|is_relative_to|strings\.HasPrefix)\b/.test(clean);
  return hasCanonicalize && hasContainmentCheck;
}

function isSsrfResourceUriTemplate(uriTemplate: string): boolean {
  const trimmed = (uriTemplate || '').trim();
  // 1. Variable inside HTTP(S) authority/host before first path slash: https://{host}/x or https://api.{host}/x
  if (/^https?:\/\/[^/?#]*\{[^}]+\}/i.test(trimmed)) return true;
  // 2. Variable scheme or full URL expansion at start: {url}, {+url}, {scheme}://{host}/x
  if (/^\{[+#./;?&]?[A-Za-z0-9_]+\}(?::\/\/|\/|$)/.test(trimmed)) return true;
  if (/^[A-Za-z0-9+.-]*\{[^}]+\}[A-Za-z0-9+.-]*:\/\//.test(trimmed)) return true;
  return false;
}

/**
 * TC-RES-003 (D5): Checks MCP resource templates for path-traversal URI variables, SSRF hosts, and missing mimeType.
 */
export function runResourceTemplateSecurityCheck(
  resourceTemplates?: McpResourceTemplateDefinition[],
  sourceFiles?: StaticSourceFile[]
): CheckResult {
  const start = Date.now();
  const templates = resourceTemplates || [];

  const hasGuardForTemplate = (tpl: McpResourceTemplateDefinition): boolean => {
    if (!sourceFiles || sourceFiles.length === 0) return false;
    if (tpl.sourceFile) {
      const matching = sourceFiles.find((f) => f.path === tpl.sourceFile || f.path.endsWith(tpl.sourceFile!));
      if (matching) {
        return fileHasRealPathContainmentGuard(matching.content);
      }
    }
    return sourceFiles.some((f) => fileHasRealPathContainmentGuard(f.content));
  };

  const ssrfTemplates = templates.filter((t) => isSsrfResourceUriTemplate(t.uriTemplate));
  const traversalTemplates = templates.filter(
    (t) =>
      !isSsrfResourceUriTemplate(t.uriTemplate) &&
      /^file:\/\//i.test(t.uriTemplate) &&
      /\{[^}]+\}/.test(t.uriTemplate) &&
      !hasGuardForTemplate(t)
  );
  const missingMime = templates.filter((t) => !t.mimeType);

  if (traversalTemplates.length > 0) {
    return {
      checkId: 'TC-RES-003',
      dimension: 'D5',
      tool: '_resources',
      status: 'FAIL',
      severity: 'HIGH',
      vetoClass: 'VETO_TRAVERSAL',
      description: `Resource URI template exposes parameterized file:// path without path.resolve prefix containment: ${traversalTemplates.map((t) => t.uriTemplate).join(', ')}.`,
      evidence: { evidenceQuality: 'STATIC-ONLY', details: { traversalTemplates } },
      durationMs: Date.now() - start,
    };
  }

  if (ssrfTemplates.length > 0) {
    return {
      checkId: 'TC-RES-003',
      dimension: 'D5',
      tool: '_resources',
      status: 'FAIL',
      severity: 'HIGH',
      vetoClass: 'VETO_EXFIL',
      description: `Resource URI template allows arbitrary host substitution (${ssrfTemplates.map((t) => t.uriTemplate).join(', ')}), creating an SSRF vector.`,
      evidence: { evidenceQuality: 'STATIC-ONLY', details: { ssrfTemplates } },
      durationMs: Date.now() - start,
    };
  }

  if (missingMime.length > 0) {
    return {
      checkId: 'TC-RES-003',
      dimension: 'D5',
      tool: '_resources',
      status: 'WARN',
      severity: 'LOW',
      description: `${missingMime.length} MCP resource template(s) omit explicit mimeType metadata.`,
      evidence: { evidenceQuality: 'STATIC-ONLY', details: { missingMime: missingMime.map((t) => t.uriTemplate) } },
      durationMs: Date.now() - start,
    };
  }

  return {
    checkId: 'TC-RES-003',
    dimension: 'D5',
    tool: '_resources',
    status: 'PASS',
    severity: 'INFO',
    description: `Analyzed ${templates.length} MCP resource template(s) with zero URI traversal or SSRF risks.`,
    evidence: { evidenceQuality: 'STATIC-ONLY', details: { templateCount: templates.length } },
    durationMs: Date.now() - start,
  };
}

/**
 * TC-OUTPUT-002 (D4): Static inspection of MCP 2025-03-26+ `outputSchema` presence and secret-field disclosure.
 */
export function runStaticOutputSchemaCheck(tool: McpToolDefinition): CheckResult {
  const start = Date.now();
  if (tool.outputSchema && typeof tool.outputSchema === 'object') {
    const props = tool.outputSchema.properties || {};
    const leakedKeys = Object.keys(props).filter((k) => SENSITIVE_OUTPUT_KEY_PATTERN.test(k));
    if (leakedKeys.length > 0) {
      return {
        checkId: 'TC-OUTPUT-002',
        dimension: 'D4',
        tool: tool.name,
        status: 'FAIL',
        severity: 'CRITICAL',
        vetoClass: 'VETO_EXFIL',
        description: `VETO_EXFIL: Tool '${tool.name}' outputSchema exposes sensitive credential/PII field(s): ${leakedKeys.join(', ')}.`,
        evidence: { evidenceQuality: 'STATIC-ONLY', details: { leakedKeys } },
        durationMs: Date.now() - start,
      };
    }

    if (tool.outputSchema.type !== 'object' && !Array.isArray(tool.outputSchema.oneOf) && !Array.isArray(tool.outputSchema.anyOf)) {
      return {
        checkId: 'TC-OUTPUT-002',
        dimension: 'D4',
        tool: tool.name,
        status: 'WARN',
        severity: 'LOW',
        description: `Tool '${tool.name}' outputSchema should specify root type 'object' per MCP structuredContent specification.`,
        evidence: { evidenceQuality: 'STATIC-ONLY', details: { outputSchema: tool.outputSchema } },
        durationMs: Date.now() - start,
      };
    }

    return {
      checkId: 'TC-OUTPUT-002',
      dimension: 'D4',
      tool: tool.name,
      status: 'PASS',
      severity: 'INFO',
      description: `Tool '${tool.name}' defines a valid MCP structured outputSchema with no secret leakage.`,
      evidence: { evidenceQuality: 'STATIC-ONLY', details: { outputProperties: Object.keys(props) } },
      durationMs: Date.now() - start,
    };
  }

  return {
    checkId: 'TC-OUTPUT-002',
    dimension: 'D4',
    tool: tool.name,
    status: 'WARN',
    severity: 'LOW',
    description: `Tool '${tool.name}' omits MCP 2025-03-26+ outputSchema for deterministic structured result validation.`,
    evidence: { evidenceQuality: 'STATIC-ONLY', details: { hasOutputSchema: false } },
    fix: {
      summary: 'Define `outputSchema` alongside `inputSchema` so clients can strictly validate structuredContent.',
      diffs: [
        {
          language: 'json-schema',
          code: `outputSchema: { type: "object", properties: { status: { type: "string" } }, required: ["status"] }`,
        },
      ],
    },
    durationMs: Date.now() - start,
  };
}
