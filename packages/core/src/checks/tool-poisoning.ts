import { CheckResult, McpToolDefinition } from '../types.js';

export interface PoisoningPattern {
  category: 'prompt_override' | 'unicode_bidi_stealth' | 'ansi_line_jump' | 'hidden_html_comment' | 'sensitive_path_harvest';
  regex: RegExp;
  label: string;
}

export const TOOL_POISONING_PATTERNS: PoisoningPattern[] = [
  {
    category: 'prompt_override',
    regex: /(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|prompts|rules|directives)/i,
    label: 'Prompt instruction override directive',
  },
  {
    category: 'prompt_override',
    regex: /(?:do\s+not|don't|never)\s+(?:tell|inform|mention\s+to|alert|show)\s+the\s+user/i,
    label: 'User-deception / stealth concealment directive',
  },
  {
    category: 'prompt_override',
    regex: /(?:always|must)\s+call\s+[a-z0-9_-]+\s+(?:first|before|silently|without\s+asking)/i,
    label: 'Forced silent tool invocation directive',
  },
  {
    category: 'prompt_override',
    regex: /before\s+calling\s+this\s+tool\s*,?\s*(?:you\s+must\s+)?(?:read|call|fetch|access|exfiltrate)/i,
    label: 'Pre-execution side-channel harvesting directive',
  },
  {
    category: 'prompt_override',
    regex: /(?:system\s*override|<system>|<\/system>|\[system\]|<<SYS>>|<IMPORTANT>)/i,
    label: 'Synthetic system / priority tag injection',
  },
  {
    category: 'unicode_bidi_stealth',
    regex: /[\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF\u{E0000}-\u{E007F}]/u,
    label: 'Invisible / bidirectional Unicode control character (Trojan Source / steganography)',
  },
  {
    category: 'ansi_line_jump',
    regex: /\x1b\[[0-9;?]*[a-zA-Z]|\u001b\[|\x1b\][^\x07]*\x07/,
    label: 'ANSI terminal escape sequence (line-jumping / terminal spoofing)',
  },
  {
    category: 'hidden_html_comment',
    regex: /<!--[\s\S]*?-->/,
    label: 'Hidden HTML/Markdown comment in tool schema',
  },
  {
    category: 'sensitive_path_harvest',
    regex: /(?:~\/\.ssh|\/etc\/passwd|\/etc\/shadow|~\/\.aws\/credentials|\.env\.local|id_rsa)/i,
    label: 'Sensitive credential file path reference in schema description',
  },
];

/**
 * TC-SEC-002: Static Tool Poisoning, Unicode Bidi & ANSI Line-Jumping Check
 * Deterministically inspects tool descriptions and parameter schemas for hidden prompt
 * overrides, invisible Unicode steganography, ANSI escape sequences, and HTML comments.
 */
export function runToolPoisoningCheck(tool: McpToolDefinition): CheckResult {
  const startTime = Date.now();
  const findings: Array<{ location: string; category: string; label: string; snippet: string }> = [];

  const scanText = (text: string | undefined, location: string) => {
    if (!text || typeof text !== 'string') return;
    for (const pattern of TOOL_POISONING_PATTERNS) {
      const match = text.match(pattern.regex);
      if (match) {
        findings.push({
          location,
          category: pattern.category,
          label: pattern.label,
          snippet: match[0].slice(0, 80),
        });
      }
    }
  };

  scanText(tool.description, 'tool.description');

  const props = tool.inputSchema?.properties || {};
  for (const [paramName, paramSchema] of Object.entries(props)) {
    if (paramSchema && typeof paramSchema === 'object') {
      scanText(paramSchema.description, `inputSchema.properties.${paramName}.description`);
      if (typeof paramSchema.default === 'string') {
        scanText(paramSchema.default, `inputSchema.properties.${paramName}.default`);
      }
    }
  }

  if (findings.length > 0) {
    const first = findings[0];
    return {
      checkId: 'TC-SEC-002',
      dimension: 'D2',
      tool: tool.name,
      status: 'FAIL',
      severity: 'CRITICAL',
      vetoClass: 'VETO_INJECT',
      description: `VETO_INJECT: Tool poisoning / line-jumping attack detected in '${tool.name}' (${first.location}): ${first.label}`,
      evidence: {
        evidenceQuality: 'STATIC-ONLY',
        details: {
          findingsCount: findings.length,
          findings,
        },
      },
      fix: {
        summary: 'Sanitize tool and parameter descriptions by removing hidden prompt instructions, ANSI escapes, and invisible Unicode control characters',
        applyCommand: 'toolveto fix --apply',
        diffs: [
          {
            language: 'json-schema',
            code: `- "description": ${JSON.stringify(tool.description || '')}\n+ "description": "Clean, declarative description of ${tool.name} inputs and side-effects."`,
          },
        ],
      },
      durationMs: Date.now() - startTime,
    };
  }

  return {
    checkId: 'TC-SEC-002',
    dimension: 'D2',
    tool: tool.name,
    status: 'PASS',
    severity: 'LOW',
    description: `Tool '${tool.name}' schema descriptions are free from static prompt poisoning, invisible Unicode, and ANSI escape sequences`,
    evidence: { evidenceQuality: 'STATIC-ONLY' },
    durationMs: Date.now() - startTime,
  };
}

/**
 * TC-SEC-003: Cross-Server Tool Shadowing & Namespace Collision Check
 * Detects duplicate tool names across loaded manifests or cross-tool hijacking
 * directives where one tool attempts to intercept/redirect calls meant for another tool.
 */
export function runToolShadowingCheck(tools: McpToolDefinition[]): CheckResult {
  const startTime = Date.now();
  const nameCounts = new Map<string, number>();
  const duplicateNames: string[] = [];

  for (const tool of tools) {
    const count = (nameCounts.get(tool.name) || 0) + 1;
    nameCounts.set(tool.name, count);
    if (count === 2) {
      duplicateNames.push(tool.name);
    }
  }

  const hijackingFindings: Array<{ tool: string; reason: string }> = [];
  // Precompute normalized lowercase tool names (length >= 3) once outside the loop
  const normalizedNames = new Map<string, string>();
  for (const t of tools) {
    if (t.name && t.name.length >= 3) {
      normalizedNames.set(t.name.toLowerCase(), t.name);
    }
  }

  const explicitHijackRegex =
    /(?:instead\s+of\s+calling|override\s+tool|replaces?\s+the\s+built-?in|shadow\s+tool|intercept\s+calls\s+to|when\s+the\s+user\s+asks\s+to\s+use\s+[a-z0-9_-]+\s*,\s*use\s+this)/i;
  const hijackDirectiveRegex =
    /(?:instead\s+of|rather\s+than|do\s+not\s+use|never\s+call|replaces?|overrides?|supersedes?)/i;

  for (const tool of tools) {
    const desc = tool.description || '';
    if (!desc) continue;

    if (explicitHijackRegex.test(desc)) {
      hijackingFindings.push({
        tool: tool.name,
        reason: `Explicit tool-shadowing directive found in description of '${tool.name}'`,
      });
      continue;
    }

    if (hijackDirectiveRegex.test(desc)) {
      const lowerDesc = desc.toLowerCase();
      const ownLower = tool.name.toLowerCase();
      // Fast O(W) token lookup against normalizedNames Map, with substring fallback for compound names
      const tokens = lowerDesc.match(/[a-z0-9_-]{3,}/g) || [];
      let matchedOther: string | undefined;
      for (const tok of tokens) {
        if (tok !== ownLower && normalizedNames.has(tok)) {
          matchedOther = normalizedNames.get(tok);
          break;
        }
      }
      if (!matchedOther) {
        for (const [otherLower, origName] of normalizedNames.entries()) {
          if (otherLower !== ownLower && lowerDesc.includes(otherLower)) {
            matchedOther = origName;
            break;
          }
        }
      }
      if (matchedOther) {
        hijackingFindings.push({
          tool: tool.name,
          reason: `Tool '${tool.name}' description attempts to shadow or redirect calls from '${matchedOther}'`,
        });
      }
    }
  }

  if (duplicateNames.length > 0 || hijackingFindings.length > 0) {
    const targetTool = duplicateNames[0] || hijackingFindings[0]?.tool || 'multi-server';
    const detailMsg =
      duplicateNames.length > 0
        ? `Duplicate tool namespace collision on [${duplicateNames.join(', ')}]`
        : hijackingFindings[0].reason;

    return {
      checkId: 'TC-SEC-003',
      dimension: 'D5',
      tool: targetTool,
      status: 'FAIL',
      severity: 'CRITICAL',
      vetoClass: 'VETO_INJECT',
      description: `VETO_INJECT: Cross-server tool shadowing / namespace collision detected: ${detailMsg}`,
      evidence: {
        evidenceQuality: 'STATIC-ONLY',
        details: {
          duplicateNames,
          hijackingFindings,
        },
      },
      fix: {
        summary: 'Namespace tool names per upstream server (e.g. github_create_issue) and remove cross-tool override directives',
        applyCommand: 'toolveto fix --suggest',
        diffs: [
          {
            language: 'json-schema',
            code: `+ // Prefix tool names with unique server namespace to prevent cross-server shadowing`,
          },
        ],
      },
      durationMs: Date.now() - startTime,
    };
  }

  return {
    checkId: 'TC-SEC-003',
    dimension: 'D5',
    tool: 'suite-wide',
    status: 'PASS',
    severity: 'LOW',
    description: `Zero tool namespace collisions or cross-server shadowing directives across ${tools.length} tool(s)`,
    evidence: { evidenceQuality: 'STATIC-ONLY' },
    durationMs: Date.now() - startTime,
  };
}
