import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  McpPromptDefinition,
  McpResourceTemplateDefinition,
  McpToolAnnotations,
  McpToolDefinition,
  StaticSourceFile,
} from '@toolveto/core';

const IGNORED_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  '.next',
  'coverage',
  '__pycache__',
  '.venv',
  'venv',
  'target',
]);

const MAX_SOURCE_FILES = 150;
const MAX_FILE_BYTES = 256 * 1024;

/**
 * Extracts a balanced bracketed block while respecting string literals and comments.
 */
export function extractBalancedDelim(
  source: string,
  openIndex: number,
  openChar: string,
  closeChar: string
): { content: string; endIndex: number } | null {
  if (openIndex < 0 || source[openIndex] !== openChar) return null;
  let depth = 0;
  let quote: string | null = null;
  let escaped = false;

  for (let i = openIndex; i < source.length; i++) {
    const ch = source[i]!;
    if (quote) {
      if (escaped) {
        escaped = false;
      } else if (ch === '\\') {
        escaped = true;
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }

    if (ch === '/' && source[i + 1] === '/') {
      const nl = source.indexOf('\n', i);
      if (nl === -1) break;
      i = nl;
      continue;
    }
    if (ch === '/' && source[i + 1] === '*') {
      const end = source.indexOf('*/', i + 2);
      if (end === -1) break;
      i = end + 1;
      continue;
    }

    if (ch === '"' || ch === "'" || ch === '`') {
      quote = ch;
      continue;
    }

    if (ch === openChar) depth++;
    else if (ch === closeChar) {
      depth--;
      if (depth === 0) {
        return { content: source.slice(openIndex + 1, i), endIndex: i };
      }
    }
  }

  return null;
}

function splitTopLevelArgs(body: string): string[] {
  const args: string[] = [];
  let depth = 0;
  let quote: string | null = null;
  let escaped = false;
  let start = 0;

  for (let i = 0; i < body.length; i++) {
    const ch = body[i]!;
    if (quote) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      quote = ch;
      continue;
    }
    if (ch === '(' || ch === '{' || ch === '[') depth++;
    else if (ch === ')' || ch === '}' || ch === ']') depth--;
    else if (ch === ',' && depth === 0) {
      const part = body.slice(start, i).trim();
      if (part) args.push(part);
      start = i + 1;
    }
  }
  const tail = body.slice(start).trim();
  if (tail) args.push(tail);
  return args;
}

function stripQuotes(expr: string): string | undefined {
  const trimmed = expr.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'")) ||
    (trimmed.startsWith('`') && trimmed.endsWith('`'))
  ) {
    return trimmed.slice(1, -1);
  }
  return undefined;
}

function extractTopLevelPairs(objBody: string): Map<string, string> {
  const map = new Map<string, string>();
  const parts = splitTopLevelArgs(objBody);
  for (const part of parts) {
    const colonIdx = findTopLevelColon(part);
    if (colonIdx === -1) continue;
    const rawKey = part.slice(0, colonIdx).trim();
    const key = stripQuotes(rawKey) ?? rawKey;
    const val = part.slice(colonIdx + 1).trim();
    if (key) map.set(key, val);
  }
  return map;
}

function findTopLevelColon(entry: string): number {
  let depth = 0;
  let quote: string | null = null;
  let escaped = false;
  for (let i = 0; i < entry.length; i++) {
    const ch = entry[i]!;
    if (quote) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      quote = ch;
      continue;
    }
    if (ch === '(' || ch === '{' || ch === '[') depth++;
    else if (ch === ')' || ch === '}' || ch === ']') depth--;
    else if (ch === ':' && depth === 0) return i;
  }
  return -1;
}

function parseZodExprToJsonSchema(expr: string): { schema: Record<string, any>; optional: boolean } {
  const optional = /\.optional\s*\(\s*\)|\.nullable\s*\(\s*\)/.test(expr);
  const schema: Record<string, any> = {};

  if (/z\.integer\s*\(|z\.number\s*\(\s*\)\.int\b/.test(expr)) {
    schema.type = 'integer';
  } else if (/z\.number\s*\(/.test(expr)) {
    schema.type = 'number';
  } else if (/z\.boolean\s*\(/.test(expr)) {
    schema.type = 'boolean';
  } else if (/z\.array\s*\(/.test(expr)) {
    schema.type = 'array';
    const maxItemsMatch = expr.match(/\.max\s*\(\s*(\d+)\s*\)/);
    if (maxItemsMatch) schema.maxItems = Number(maxItemsMatch[1]);
  } else if (/z\.enum\s*\(\s*\[([^\]]+)\]/.test(expr)) {
    schema.type = 'string';
    const enumMatch = expr.match(/z\.enum\s*\(\s*\[([^\]]+)\]/);
    if (enumMatch?.[1]) {
      schema.enum = enumMatch[1]
        .split(',')
        .map((s) => stripQuotes(s.trim()))
        .filter((v): v is string => Boolean(v));
    }
  } else if (/z\.object\s*\(/.test(expr)) {
    schema.type = 'object';
  } else {
    schema.type = 'string';
  }

  const descMatch = expr.match(/\.describe\s*\(\s*(['"`])((?:\\.|(?!\1).)*)\1\s*\)/);
  if (descMatch?.[2]) schema.description = descMatch[2];

  if (/\.email\s*\(/.test(expr)) schema.format = 'email';
  else if (/\.url\s*\(/.test(expr)) schema.format = 'uri';
  else if (/\.uuid\s*\(/.test(expr)) schema.format = 'uuid';
  else if (/\.date\s*\(/.test(expr)) schema.format = 'date';
  else if (/\.datetime\s*\(/.test(expr)) schema.format = 'date-time';

  const minMatch = expr.match(/\.min\s*\(\s*(\d+(?:\.\d+)?)\s*\)/);
  const maxMatch = expr.match(/\.max\s*\(\s*(\d+(?:\.\d+)?)\s*\)/);
  if ((schema.type === 'number' || schema.type === 'integer') && minMatch) schema.minimum = Number(minMatch[1]);
  if ((schema.type === 'number' || schema.type === 'integer') && maxMatch) schema.maximum = Number(maxMatch[1]);
  if (schema.type === 'number' && /\.positive\s*\(/.test(expr) && schema.minimum === undefined) schema.exclusiveMinimum = 0;

  return { schema, optional };
}

function parseJsSchemaLiteral(expr: string): Record<string, any> {
  const trimmed = expr.trim();
  if (!trimmed.startsWith('{') || !trimmed.endsWith('}')) {
    return { type: 'object', properties: {} };
  }
  const inner = trimmed.slice(1, -1);
  const pairs = extractTopLevelPairs(inner);

  // Check if this is `z.object({ ... })` or raw `{ prop: z.string(), ... }` without `properties:`
  if (!pairs.has('type') && !pairs.has('properties')) {
    return parseZodShapeToSchema(inner);
  }

  const out: Record<string, any> = {
    type: stripQuotes(pairs.get('type') || '') || 'object',
    properties: {},
  };

  if (pairs.get('additionalProperties') === 'false') out.additionalProperties = false;
  if (pairs.get('additionalProperties') === 'true') out.additionalProperties = true;

  const reqVal = pairs.get('required');
  if (reqVal && reqVal.startsWith('[') && reqVal.endsWith(']')) {
    out.required = reqVal
      .slice(1, -1)
      .split(',')
      .map((s) => stripQuotes(s.trim()))
      .filter((v): v is string => Boolean(v));
  }

  const propsVal = pairs.get('properties');
  if (propsVal && propsVal.startsWith('{') && propsVal.endsWith('}')) {
    const propPairs = extractTopLevelPairs(propsVal.slice(1, -1));
    for (const [k, rawProp] of propPairs.entries()) {
      if (rawProp.startsWith('{') && rawProp.endsWith('}')) {
        const subPairs = extractTopLevelPairs(rawProp.slice(1, -1));
        const propObj: Record<string, any> = {};
        for (const [sk, sv] of subPairs.entries()) {
          const unquoted = stripQuotes(sv);
          if (unquoted !== undefined) propObj[sk] = unquoted;
          else if (sv === 'true') propObj[sk] = true;
          else if (sv === 'false') propObj[sk] = false;
          else if (/^-?\d+(\.\d+)?$/.test(sv)) propObj[sk] = Number(sv);
          else if (sv.startsWith('[') && sv.endsWith(']')) {
            propObj[sk] = sv
              .slice(1, -1)
              .split(',')
              .map((s) => stripQuotes(s.trim()) ?? s.trim())
              .filter(Boolean);
          }
        }
        out.properties[k] = propObj;
      }
    }
  }

  return out;
}

function parseZodShapeToSchema(shapeInner: string): Record<string, any> {
  const properties: Record<string, any> = {};
  const required: string[] = [];
  const pairs = extractTopLevelPairs(shapeInner);

  for (const [propName, rawVal] of pairs.entries()) {
    const { schema, optional } = parseZodExprToJsonSchema(rawVal);
    properties[propName] = schema;
    if (!optional) required.push(propName);
  }

  const res: Record<string, any> = { type: 'object', properties };
  if (required.length > 0) res.required = required;
  return res;
}

function parseAnnotationsObjectLiteral(expr?: string): McpToolAnnotations | undefined {
  if (!expr) return undefined;
  const trimmed = expr.trim();
  if (!trimmed.startsWith('{') || !trimmed.endsWith('}')) return undefined;
  const pairs = extractTopLevelPairs(trimmed.slice(1, -1));
  const annotations: McpToolAnnotations = {};
  if (pairs.has('readOnlyHint')) annotations.readOnlyHint = pairs.get('readOnlyHint') === 'true';
  if (pairs.has('destructiveHint')) annotations.destructiveHint = pairs.get('destructiveHint') === 'true';
  if (pairs.has('idempotentHint')) annotations.idempotentHint = pairs.get('idempotentHint') === 'true';
  if (pairs.has('openWorldHint')) annotations.openWorldHint = pairs.get('openWorldHint') === 'true';
  return Object.keys(annotations).length > 0 ? annotations : undefined;
}

function lineNumberAt(source: string, index: number): number {
  let lines = 1;
  for (let i = 0; i < index && i < source.length; i++) {
    if (source[i] === '\n') lines++;
  }
  return lines;
}

/**
 * Extracts MCP tools statically from TypeScript / JavaScript sources without executing code.
 */
export function parseTypeScriptSourceForTools(
  source: string,
  filePath = 'server.ts',
  language: 'typescript' | 'javascript' = 'typescript'
): McpToolDefinition[] {
  const tools: McpToolDefinition[] = [];
  const seen = new Set<string>();

  const pushUnique = (tool: McpToolDefinition) => {
    if (!tool.name || seen.has(tool.name)) return;
    seen.add(tool.name);
    tools.push(tool);
  };

  // 1. server.tool(...) / mcp.tool(...) / server.registerTool(...)
  const callRe = /\b([A-Za-z_$][\w$]*)\.(tool|registerTool)\s*\(/g;
  let match: RegExpExecArray | null;
  while ((match = callRe.exec(source)) !== null) {
    const openParen = match.index + match[0].length - 1;
    const balanced = extractBalancedDelim(source, openParen, '(', ')');
    if (!balanced) continue;

    const method = match[2];
    const args = splitTopLevelArgs(balanced.content);
    const toolName = args[0] ? stripQuotes(args[0]) : undefined;
    if (!toolName) continue;

    const line = lineNumberAt(source, match.index);
    if (method === 'registerTool' && args[1]?.trim().startsWith('{')) {
      const cfgPairs = extractTopLevelPairs(args[1].trim().slice(1, -1));
      const description = stripQuotes(cfgPairs.get('description') || '') || stripQuotes(cfgPairs.get('title') || '');
      const rawInput = cfgPairs.get('inputSchema');
      const inputSchema = rawInput ? parseJsSchemaLiteral(rawInput) : { type: 'object', properties: {} };
      const rawOutput = cfgPairs.get('outputSchema');
      const outputSchema = rawOutput ? parseJsSchemaLiteral(rawOutput) : undefined;
      const annotations = parseAnnotationsObjectLiteral(cfgPairs.get('annotations'));

      pushUnique({
        name: toolName,
        description,
        inputSchema: inputSchema as any,
        outputSchema,
        annotations,
        readOnlyHint: annotations?.readOnlyHint,
        destructiveHint: annotations?.destructiveHint,
        idempotentHint: annotations?.idempotentHint,
        openWorldHint: annotations?.openWorldHint,
        sourceLocation: { file: filePath, line, language },
      });
      continue;
    }

    // server.tool(name, [description], [schemaObjectOrZod], [annotations], callback)
    let description: string | undefined;
    let inputSchema: Record<string, any> = { type: 'object', properties: {} };
    let annotations: McpToolAnnotations | undefined;

    for (let idx = 1; idx < args.length; idx++) {
      const arg = args[idx]!.trim();
      const str = stripQuotes(arg);
      if (str !== undefined && !description) {
        description = str;
      } else if (arg.startsWith('z.object(')) {
        const zBalanced = extractBalancedDelim(arg, arg.indexOf('('), '(', ')');
        if (zBalanced && zBalanced.content.trim().startsWith('{')) {
          inputSchema = parseZodShapeToSchema(zBalanced.content.trim().slice(1, -1));
        }
      } else if (arg.startsWith('{') && arg.endsWith('}')) {
        const pairs = extractTopLevelPairs(arg.slice(1, -1));
        if (pairs.has('readOnlyHint') || pairs.has('destructiveHint') || pairs.has('idempotentHint') || pairs.has('openWorldHint')) {
          annotations = parseAnnotationsObjectLiteral(arg);
        } else {
          inputSchema = parseJsSchemaLiteral(arg);
        }
      }
    }

    pushUnique({
      name: toolName,
      description,
      inputSchema: inputSchema as any,
      annotations,
      readOnlyHint: annotations?.readOnlyHint,
      destructiveHint: annotations?.destructiveHint,
      idempotentHint: annotations?.idempotentHint,
      openWorldHint: annotations?.openWorldHint,
      sourceLocation: { file: filePath, line, language },
    });
  }

  // 2. Low-level Server JSON tools arrays (`{ name: '...', description: '...', inputSchema: { ... } }`)
  const objToolRe = /\{\s*name\s*:\s*(['"`])([a-zA-Z0-9_.-]+)\1\s*,/g;
  while ((match = objToolRe.exec(source)) !== null) {
    const balanced = extractBalancedDelim(source, match.index, '{', '}');
    if (!balanced) continue;
    const pairs = extractTopLevelPairs(balanced.content);
    const name = stripQuotes(pairs.get('name') || '');
    const rawInput = pairs.get('inputSchema');
    if (!name || !rawInput) continue;

    const description = stripQuotes(pairs.get('description') || '');
    const inputSchema = parseJsSchemaLiteral(rawInput);
    const rawOutput = pairs.get('outputSchema');
    const outputSchema = rawOutput ? parseJsSchemaLiteral(rawOutput) : undefined;
    const annotations = parseAnnotationsObjectLiteral(pairs.get('annotations'));

    pushUnique({
      name,
      description,
      inputSchema: inputSchema as any,
      outputSchema,
      annotations,
      readOnlyHint: annotations?.readOnlyHint,
      destructiveHint: annotations?.destructiveHint,
      idempotentHint: annotations?.idempotentHint,
      openWorldHint: annotations?.openWorldHint,
      sourceLocation: { file: filePath, line: lineNumberAt(source, match.index), language },
    });
  }

  return tools;
}

function mapPythonTypeToJsonSchema(typeExpr: string): Record<string, any> {
  const clean = typeExpr.trim();
  const annotatedMatch = clean.match(/^Annotated\s*\[\s*([^,]+)\s*,\s*Field\s*\(([^)]*)\)/);
  if (annotatedMatch) {
    const base = mapPythonTypeToJsonSchema(annotatedMatch[1]!);
    const fieldArgs = annotatedMatch[2]!;
    const ge = fieldArgs.match(/\bge\s*=\s*(-?\d+(?:\.\d+)?)/);
    const gt = fieldArgs.match(/\bgt\s*=\s*(-?\d+(?:\.\d+)?)/);
    const le = fieldArgs.match(/\ble\s*=\s*(-?\d+(?:\.\d+)?)/);
    const desc = fieldArgs.match(/description\s*=\s*(['"])((?:\\.|(?!\1).)*)\1/);
    if (ge) base.minimum = Number(ge[1]);
    if (gt) base.exclusiveMinimum = Number(gt[1]);
    if (le) base.maximum = Number(le[1]);
    if (desc?.[2]) base.description = desc[2];
    return base;
  }

  const literalMatch = clean.match(/^Literal\s*\[\s*([^\]]+)\s*\]/);
  if (literalMatch?.[1]) {
    return {
      type: 'string',
      enum: literalMatch[1]
        .split(',')
        .map((s) => stripQuotes(s.trim()))
        .filter((v): v is string => Boolean(v)),
    };
  }

  if (/^Optional\s*\[(.+)\]$/.test(clean)) {
    const inner = clean.replace(/^Optional\s*\[(.+)\]$/, '$1');
    return mapPythonTypeToJsonSchema(inner);
  }
  if (/^(int|integer)$/i.test(clean)) return { type: 'integer' };
  if (/^(float|Decimal|number)$/i.test(clean)) return { type: 'number' };
  if (/^bool(ean)?$/i.test(clean)) return { type: 'boolean' };
  if (/^(list|List|Sequence)\b/.test(clean)) return { type: 'array' };
  if (/^(dict|Dict|Mapping)\b/.test(clean)) return { type: 'object' };
  return { type: 'string' };
}

/**
 * Extracts MCP `@mcp.tool()`, `@gr.mcp.tool()`, NVIDIA NeMo `@register_function`,
 * and Hugging Face Gradio `mcp_server=True` tool definitions statically from Python files.
 */
export function parsePythonSourceForTools(source: string, filePath = 'server.py'): McpToolDefinition[] {
  const tools: McpToolDefinition[] = [];
  const seen = new Set<string>();

  const stripPythonComments = (raw: string): string => {
    let out = '';
    let quote: string | null = null;
    let escaped = false;
    for (let i = 0; i < raw.length; i++) {
      const ch = raw[i]!;
      if (quote) {
        out += ch;
        if (escaped) escaped = false;
        else if (ch === '\\') escaped = true;
        else if (ch === quote) quote = null;
        continue;
      }
      if (ch === '"' || ch === "'") {
        quote = ch;
        out += ch;
        continue;
      }
      if (ch === '#') {
        while (i < raw.length && raw[i] !== '\n') i++;
        if (i < raw.length) out += '\n';
        continue;
      }
      out += ch;
    }
    return out;
  };

  const parsePythonParams = (paramsContent: string): { properties: Record<string, any>; required: string[] } => {
    const properties: Record<string, any> = {};
    const required: string[] = [];
    const uncommented = stripPythonComments(paramsContent);
    for (const rawParam of splitTopLevelArgs(uncommented)) {
      const cleaned = rawParam.trim();
      if (
        !cleaned ||
        cleaned === '/' ||
        cleaned === 'self' ||
        cleaned === 'cls' ||
        cleaned.startsWith('*') ||
        /\bContext\b/.test(cleaned) ||
        /\bgr\.(?:Progress|Request)\b/.test(cleaned)
      ) {
        continue;
      }

      const eqIdx = findTopLevelEquals(cleaned);
      const hasDefault = eqIdx !== -1;
      const declPart = (hasDefault ? cleaned.slice(0, eqIdx) : cleaned).trim();
      const colonIdx = findTopLevelColon(declPart);
      const paramName = (colonIdx !== -1 ? declPart.slice(0, colonIdx) : declPart).trim();
      if (
        !paramName ||
        !/^[A-Za-z_]\w*$/.test(paramName) ||
        paramName === 'ctx' ||
        paramName === 'progress' ||
        paramName === 'request'
      ) {
        continue;
      }

      const typeExpr = colonIdx !== -1 ? declPart.slice(colonIdx + 1).trim() : 'str';
      properties[paramName] = mapPythonTypeToJsonSchema(typeExpr);

      if (!hasDefault && !/^Optional\s*\[/.test(typeExpr) && !/\|\s*None\b/.test(typeExpr)) {
        required.push(paramName);
      }
    }
    return { properties, required };
  };

  // 1. Decorated MCP / FastMCP / Gradio @gr.mcp.tool / NVIDIA NeMo @register_function handlers
  const decoRe =
    /@(?:[A-Za-z_][\w.]*\.tool|register_function|register_tool)\s*(?:\(([^)]*)\))?\s*(?:\r?\n\s*@[A-Za-z_][\w.]*(?:\([^)]*\))?)*\s*\r?\n\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/g;
  let match: RegExpExecArray | null;

  while ((match = decoRe.exec(source)) !== null) {
    const decoratorArgs = match[1] || '';
    const fnName = match[2]!;
    const paramsOpen = match.index + match[0].length - 1;
    const balancedParams = extractBalancedDelim(source, paramsOpen, '(', ')');
    if (!balancedParams) continue;

    const afterParams = source.slice(balancedParams.endIndex + 1, balancedParams.endIndex + 400);
    const docMatch = afterParams.match(/^\s*(?:->[^:]+)?:\s*\r?\n\s*(?:"""([\s\S]*?)"""|'''([\s\S]*?)''')/);
    const docstring = (docMatch?.[1] || docMatch?.[2] || '').trim().replace(/\s+/g, ' ');

    const decNameMatch = decoratorArgs.match(/name\s*=\s*(['"])([^'"]+)\1/);
    const decDescMatch = decoratorArgs.match(/description\s*=\s*(['"])([^'"]+)\1/);
    const toolName = decNameMatch?.[2] || fnName;
    if (seen.has(toolName)) continue;
    seen.add(toolName);

    const { properties, required } = parsePythonParams(balancedParams.content);

    const annotations: McpToolAnnotations = {};
    const ro = decoratorArgs.match(/readOnlyHint\s*[:=]\s*(True|False)/);
    const dest = decoratorArgs.match(/destructiveHint\s*[:=]\s*(True|False)/);
    const idemp = decoratorArgs.match(/idempotentHint\s*[:=]\s*(True|False)/);
    const ow = decoratorArgs.match(/openWorldHint\s*[:=]\s*(True|False)/);
    if (ro) annotations.readOnlyHint = ro[1] === 'True';
    if (dest) annotations.destructiveHint = dest[1] === 'True';
    if (idemp) annotations.idempotentHint = idemp[1] === 'True';
    if (ow) annotations.openWorldHint = ow[1] === 'True';

    tools.push({
      name: toolName,
      description: decDescMatch?.[2] || docstring || undefined,
      inputSchema: { type: 'object', properties, ...(required.length > 0 ? { required } : {}) },
      ...(Object.keys(annotations).length > 0 ? { annotations, ...annotations } : {}),
      sourceLocation: { file: filePath, line: lineNumberAt(source, match.index), language: 'python' },
    });
  }

  // 2. Hugging Face Gradio MCP Spaces (`demo.launch(..., mcp_server=True)`)
  // Gradio 5+ exposes gr.Interface(fn=...), gr.api(fn), and public .click/.then/.submit(fn=..., api_name=...) handlers as MCP tools.
  if (/\bmcp_server\s*=\s*True\b/.test(source)) {
    const fnDefs = new Map<
      string,
      { paramsContent: string; docstring: string; line: number }
    >();
    const defRe = /^[ \t]*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/gm;
    let dm: RegExpExecArray | null;
    while ((dm = defRe.exec(source)) !== null) {
      const name = dm[1]!;
      const openIdx = dm.index + dm[0].length - 1;
      const balanced = extractBalancedDelim(source, openIdx, '(', ')');
      if (!balanced) continue;
      const after = source.slice(balanced.endIndex + 1, balanced.endIndex + 600);
      const docM = after.match(/^\s*(?:->[^:]+)?:\s*\r?\n\s*(?:"""([\s\S]*?)"""|'''([\s\S]*?)''')/);
      const docstring = (docM?.[1] || docM?.[2] || '').trim().replace(/\s+/g, ' ');
      if (!fnDefs.has(name)) {
        fnDefs.set(name, {
          paramsContent: balanced.content,
          docstring,
          line: lineNumberAt(source, dm.index),
        });
      }
    }

    const exposedGradioHandlers: Array<{ fnName: string; apiName?: string; description?: string }> = [];

    // 2a. gr.Interface(...) / gradio.Interface(...)
    const ifaceRe = /\b(?:gr|gradio)\.Interface\s*\(/g;
    let im: RegExpExecArray | null;
    while ((im = ifaceRe.exec(source)) !== null) {
      const openIdx = im.index + im[0].length - 1;
      const balanced = extractBalancedDelim(source, openIdx, '(', ')');
      if (!balanced) continue;
      const args = splitTopLevelArgs(balanced.content);
      let fnName: string | undefined;
      let apiName: string | undefined;
      let ifaceDesc: string | undefined;
      for (let i = 0; i < args.length; i++) {
        const arg = args[i]!.trim();
        const fnKw = arg.match(/^fn\s*=\s*([A-Za-z_]\w*)$/);
        if (fnKw) fnName = fnKw[1];
        else if (i === 0 && /^[A-Za-z_]\w*$/.test(arg)) fnName = arg;
        const apiKw = arg.match(/^api_name\s*=\s*(['"])([^'"]+)\1/);
        if (apiKw) apiName = apiKw[2];
        const descKw = arg.match(/^(?:description|title)\s*=\s*(['"])([^'"]+)\1/);
        if (descKw && !ifaceDesc) ifaceDesc = descKw[2];
      }
      if (fnName && !/\bapi_name\s*=\s*False\b/.test(balanced.content)) {
        exposedGradioHandlers.push({ fnName, apiName, description: ifaceDesc });
      }
    }

    // 2b. gr.api(fn, ...)
    const apiRe = /\b(?:gr|gradio)\.api\s*\(/g;
    while ((im = apiRe.exec(source)) !== null) {
      const openIdx = im.index + im[0].length - 1;
      const balanced = extractBalancedDelim(source, openIdx, '(', ')');
      if (!balanced) continue;
      const args = splitTopLevelArgs(balanced.content);
      const first = args[0]?.trim() || '';
      const fnKw = first.match(/^(?:fn\s*=\s*)?([A-Za-z_]\w*)$/);
      const apiKw = balanced.content.match(/\bapi_name\s*=\s*(['"])([^'"]+)\1/);
      if (fnKw && fnKw[1]) {
        exposedGradioHandlers.push({ fnName: fnKw[1], apiName: apiKw?.[2] });
      }
    }

    // 2c. .click(...) / .then(...) / .submit(...) with explicit public api_name or non-private fn
    const eventRe = /\.(?:click|then|submit)\s*\(/g;
    while ((im = eventRe.exec(source)) !== null) {
      const openIdx = im.index + im[0].length - 1;
      const balanced = extractBalancedDelim(source, openIdx, '(', ')');
      if (!balanced) continue;
      const body = balanced.content;
      if (/\bapi_visibility\s*=\s*['"]private['"]/.test(body) || /\bapi_name\s*=\s*False\b/.test(body)) {
        continue;
      }
      const args = splitTopLevelArgs(body);
      let fnName: string | undefined;
      let apiName: string | undefined;
      for (let i = 0; i < args.length; i++) {
        const arg = args[i]!.trim();
        const fnKw = arg.match(/^fn\s*=\s*([A-Za-z_]\w*)$/);
        if (fnKw) fnName = fnKw[1];
        else if (i === 0 && /^[A-Za-z_]\w*$/.test(arg) && arg !== 'None') fnName = arg;
        const apiKw = arg.match(/^api_name\s*=\s*(['"])([^'"]+)\1/);
        if (apiKw) apiName = apiKw[2];
      }
      if (fnName && !fnName.startsWith('_') && (apiName || fnDefs.has(fnName))) {
        exposedGradioHandlers.push({ fnName, apiName });
      }
    }

    for (const handler of exposedGradioHandlers) {
      const def = fnDefs.get(handler.fnName);
      if (!def) continue;
      const toolName = (handler.apiName || handler.fnName).replace(/^\/+/, '');
      if (!toolName || seen.has(toolName)) continue;
      seen.add(toolName);
      const { properties, required } = parsePythonParams(def.paramsContent);
      tools.push({
        name: toolName,
        description: def.docstring || handler.description || undefined,
        inputSchema: { type: 'object', properties, ...(required.length > 0 ? { required } : {}) },
        sourceLocation: { file: filePath, line: def.line, language: 'python' },
      });
    }
  }

  return tools;
}

function findTopLevelEquals(entry: string): number {
  let depth = 0;
  let quote: string | null = null;
  let escaped = false;
  for (let i = 0; i < entry.length; i++) {
    const ch = entry[i]!;
    if (quote) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === '(' || ch === '{' || ch === '[') depth++;
    else if (ch === ')' || ch === '}' || ch === ']') depth--;
    else if (ch === '=' && depth === 0) return i;
  }
  return -1;
}

/**
 * Extracts MCP resource templates and prompts statically from TS/JS/Python sources.
 */
export function extractResourcesAndPromptsFromSource(
  source: string,
  filePath: string
): { resourceTemplates: McpResourceTemplateDefinition[]; prompts: McpPromptDefinition[] } {
  const resourceTemplates: McpResourceTemplateDefinition[] = [];
  const prompts: McpPromptDefinition[] = [];

  // TypeScript/JS `server.resource("name", new ResourceTemplate("file://{path}", ...), ...)` or string URI
  const tsResRe = /\.\s*(?:resource|registerResource)\s*\(\s*(['"`])([^'"`]+)\1\s*,\s*(?:new\s+ResourceTemplate\s*\(\s*)?(['"`])([^'"`]+)\3/g;
  let m: RegExpExecArray | null;
  while ((m = tsResRe.exec(source)) !== null) {
    const snippet = source.slice(m.index, m.index + 320);
    const mimeMatch = snippet.match(/mimeType\s*:\s*(['"`])([^'"`]+)\1/);
    resourceTemplates.push({
      name: m[2]!,
      uriTemplate: m[4]!,
      mimeType: mimeMatch?.[2],
      sourceFile: filePath,
    });
  }

  // Python `@mcp.resource("scheme://{var}", mime_type="...")`
  const pyResRe = /@[A-Za-z_][\w.]*\.resource\s*\(\s*(['"])([^'"]+)\1([^)]*)\)/g;
  while ((m = pyResRe.exec(source)) !== null) {
    const kwargs = m[3] || '';
    const mimeMatch = kwargs.match(/mime_type\s*=\s*(['"])([^'"]+)\1/);
    const nameMatch = kwargs.match(/name\s*=\s*(['"])([^'"]+)\1/);
    resourceTemplates.push({
      name: nameMatch?.[2] || m[2]!,
      uriTemplate: m[2]!,
      mimeType: mimeMatch?.[2],
      sourceFile: filePath,
    });
  }

  // TS `server.prompt("name", ...)` and Python `@mcp.prompt(...) def name(...)`
  const tsPromptRe = /\.\s*(?:prompt|registerPrompt)\s*\(\s*(['"`])([^'"`]+)\1(?:\s*,\s*(['"`])([^'"`]*)\3)?/g;
  while ((m = tsPromptRe.exec(source)) !== null) {
    prompts.push({
      name: m[2]!,
      description: m[4],
      sourceFile: filePath,
    });
  }

  const pyPromptRe = /@[A-Za-z_][\w.]*\.prompt\s*(?:\(([^)]*)\))?\s*\r?\n(?:async\s+)?def\s+([A-Za-z_]\w*)/g;
  while ((m = pyPromptRe.exec(source)) !== null) {
    prompts.push({
      name: m[2]!,
      description: m[1],
      sourceFile: filePath,
    });
  }

  return { resourceTemplates, prompts };
}

function detectLanguage(filePath: string): StaticSourceFile['language'] | null {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === '.ts' || ext === '.tsx') return 'typescript';
  if (ext === '.js' || ext === '.mjs' || ext === '.cjs') return 'javascript';
  if (ext === '.py') return 'python';
  if (ext === '.go') return 'go';
  return null;
}

/**
 * Walks a target file or repository directory cleanly (up to 150 bounded files) and extracts
 * TypeScript/JS/Python MCP tools, resource templates, prompts, transport mode, and bounded source files.
 */
export function extractSourceContextFromDir(targetPath: string): {
  tools: McpToolDefinition[];
  sourceFiles: StaticSourceFile[];
  resourceTemplates: McpResourceTemplateDefinition[];
  prompts: McpPromptDefinition[];
  transportMode: 'stdio' | 'http' | 'sse' | 'dual' | 'unknown';
} {
  const tools: McpToolDefinition[] = [];
  const seenToolNames = new Set<string>();
  const sourceFiles: StaticSourceFile[] = [];
  const resourceTemplates: McpResourceTemplateDefinition[] = [];
  const prompts: McpPromptDefinition[] = [];

  if (!targetPath || /^https?:\/\//i.test(targetPath) || !fs.existsSync(targetPath)) {
    return { tools, sourceFiles, resourceTemplates, prompts, transportMode: 'unknown' };
  }

  const collectFile = (absPath: string, relPath: string) => {
    if (sourceFiles.length >= MAX_SOURCE_FILES) return;
    const lang = detectLanguage(absPath);
    if (!lang) return;
    try {
      const stat = fs.statSync(absPath);
      if (!stat.isFile() || stat.size > MAX_FILE_BYTES) return;
      const content = fs.readFileSync(absPath, 'utf-8');
      sourceFiles.push({ path: relPath, language: lang, content });

      const extractedTools =
        lang === 'python'
          ? parsePythonSourceForTools(content, relPath)
          : lang === 'typescript' || lang === 'javascript'
          ? parseTypeScriptSourceForTools(content, relPath, lang)
          : [];

      for (const t of extractedTools) {
        if (!seenToolNames.has(t.name)) {
          seenToolNames.add(t.name);
          tools.push(t);
        }
      }

      const rp = extractResourcesAndPromptsFromSource(content, relPath);
      resourceTemplates.push(...rp.resourceTemplates);
      prompts.push(...rp.prompts);
    } catch {
      // Unreadable file ignored
    }
  };

  const stat = fs.lstatSync(targetPath);
  if (stat.isSymbolicLink()) {
    return { tools, sourceFiles, resourceTemplates, prompts, transportMode: 'unknown' };
  }
  if (stat.isFile()) {
    collectFile(targetPath, path.basename(targetPath));
  } else if (stat.isDirectory()) {
    let realTargetRoot: string;
    try {
      realTargetRoot = fs.realpathSync(targetPath);
    } catch {
      return { tools, sourceFiles, resourceTemplates, prompts, transportMode: 'unknown' };
    }
    const visitedDirs = new Set<string>([realTargetRoot]);

    const walk = (dir: string) => {
      if (sourceFiles.length >= MAX_SOURCE_FILES) return;
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const entry of entries) {
        if (sourceFiles.length >= MAX_SOURCE_FILES) break;
        if (IGNORED_DIRS.has(entry.name)) continue;
        if (entry.isSymbolicLink()) continue;
        const full = path.join(dir, entry.name);
        let realFull: string;
        try {
          realFull = fs.realpathSync(full);
        } catch {
          continue;
        }
        const rel = path.relative(realTargetRoot, realFull);
        if (rel.startsWith('..') || path.isAbsolute(rel)) continue;

        if (entry.isDirectory()) {
          if (visitedDirs.has(realFull)) continue;
          visitedDirs.add(realFull);
          walk(full);
        } else if (entry.isFile()) {
          collectFile(realFull, path.relative(targetPath, full));
        }
      }
    };
    walk(targetPath);
  }

  let hasStdio = false;
  let hasHttp = false;
  let hasSse = false;
  for (const f of sourceFiles) {
    if (/\bStdioServerTransport\b|transport\s*=\s*["']stdio["']|stdio_server|process\.stdin/.test(f.content)) hasStdio = true;
    if (/\bStreamableHTTPServerTransport\b|\bhttp\.createServer\b/.test(f.content)) hasHttp = true;
    if (/\bSSEServerTransport\b|\bmcp_server\s*=\s*True\b/.test(f.content)) hasSse = true;
  }

  const transportMode =
    hasStdio && (hasHttp || hasSse) ? 'dual' : hasHttp ? 'http' : hasSse ? 'sse' : hasStdio ? 'stdio' : 'unknown';

  return { tools, sourceFiles, resourceTemplates, prompts, transportMode };
}
