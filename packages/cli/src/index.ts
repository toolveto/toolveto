import { Command } from 'commander';
import { checkCommand } from './commands/check.js';
import { fixCommand } from './commands/fix.js';
import { proxyCommand } from './commands/proxy.js';
import { badgeCommand } from './commands/badge.js';
import { evidenceCommand } from './commands/evidence.js';
import { loginCommand } from './commands/login.js';
import { verifyCommand } from './commands/verify.js';
import { lockCommand } from './commands/lock.js';
import { exportPolicyCommand } from './commands/export-policy.js';
import { wrapCommand } from './commands/wrap.js';

export function createProgram(): Command {
  const program = new Command();

  program
    .name('toolveto')
    .description('Deterministic Chaos Testing, CI Blocking Gates & Auto-Remediation for MCP Servers')
    .version('0.2.0');

  program
    .command('check')
    .description('Run deterministic checks on an MCP server (<90s, $0, zero LLM)')
    .argument('<target>', 'Path to local MCP server directory, binary, or Streamable HTTP URL')
    .option('--with-llm', 'Enable Stage 4 LLM E_heal self-heal judge (requires API key)')
    .option('--allow-destructive', 'Authorize live stateful replay and concurrent burst mutations (D1)')
    .option('--allow-exec', 'Authorize spawning local server entrypoint scripts discovered inside target directory')
    .option('--ephemeral-mock', 'Zero-setup ephemeral mock evaluation on static manifests with live VERIFIED runtime evidence')
    .option('--json', 'Output machine-readable JSON report')
    .option('-f, --format <format>', 'Output format: terminal, json, or github-pr', 'terminal')
    .option('-t, --threshold <score>', 'Minimum certification score threshold (0-100)')
    .option('--fail-on-severity <severity>', 'Fail with exit code 1 if any failed check meets or exceeds severity (LOW, MEDIUM, HIGH, CRITICAL)')
    .option('--demo', 'Allow synthetic mock tools when target has zero tools (demo mode)')
    .option('--skip-update-check', 'Skip checking for new ToolVeto CLI versions and update notices (Trivy/Grype compatible)')
    .option('--no-telemetry', 'Disable anonymous CLI run telemetry (or set DO_NOT_TRACK=1 / TOOLVETO_NO_TELEMETRY=1)')
    .action(async (target, options) => {
      await checkCommand(target, options);
    });

  program
    .command('wrap')
    .description('Wrap MCP servers in Cursor, Claude Desktop, or Windsurf config with @toolveto/shield runtime protection')
    .argument('[target]', 'Path to MCP client config file (.cursor/mcp.json, claude_desktop_config.json) or directory')
    .option('-c, --client <client>', 'Target MCP client: cursor | claude | windsurf | auto', 'auto')
    .option('--token-budget <tokens>', 'Max response tokens per tool call', '4000')
    .option('--strict', 'Enable fail-closed strict mode on Shield proxy')
    .option('--unwrap', 'Restore original unwrapped server commands from _toolvetoOriginal metadata')
    .option('--dry-run', 'Print the wrapped configuration JSON without writing to disk')
    .action(async (target, options) => {
      await wrapCommand(target, options);
    });

  program
    .command('fix')
    .description('Auto-apply deterministic AST schema fixes + optional LLM handler code synthesis (--with-llm)')
    .argument('[target]', 'Path to schema file or server directory')
    .option('--apply', 'Directly modify local JSON schema or source code files on disk')
    .option('--suggest', 'Print multi-language AST diffs and generate toolveto-remediation.patch')
    .option('-c, --check <checkId>', 'Target a specific check ID for remediation (e.g., TC-IDEMP-001)')
    .option('--with-llm', 'Enable Tier-2 LLM code patch synthesis for imperative tool handler bodies (uses ANTHROPIC_API_KEY, OPENAI_API_KEY, or GEMINI_API_KEY)')
    .option('--llm-provider <provider>', 'LLM provider for handler synthesis: anthropic | openai | gemini | auto', 'auto')
    .option('--model <model>', 'Override LLM model identifier for handler code synthesis')
    .action(async (target, options) => {
      await fixCommand(target, options);
    });

  program
    .command('proxy')
    .description('Launch ToolVeto Shield runtime reverse proxy gateway')
    .option('-p, --port <port>', 'Proxy port to listen on', '8080')
    .option('-u, --upstream <url>', 'Upstream MCP server URL', 'http://localhost:3000/mcp')
    .option('-t, --token-budget <tokens>', 'Maximum token ceiling for response truncation', '4000')
    .action(async (options) => {
      await proxyCommand(options);
    });

  program
    .command('badge')
    .description('Generate an official ToolVeto SVG badge for README markdown')
    .option('-s, --score <score>', 'Evaluated score (0-100)')
    .option('-t, --tier <tier>', 'Certification tier (Platinum, Gold, Silver, Bronze, Rejected)')
    .option('-o, --output <path>', 'Output SVG file path', 'toolveto-badge.svg')
    .action(async (options) => {
      await badgeCommand(options);
    });

  program
    .command('evidence')
    .description('Generate an AIUC-1 / OWASP compliant JWS-signed evidence packet for CISO review')
    .argument('[target]', 'Target server path or schema file')
    .option('-f, --format <format>', 'Output format: aiuc1, owasp, json', 'aiuc1')
    .option('-t, --target <path>', 'Target server path or schema file', '.')
    .option('-o, --output <path>', 'Output file destination')
    .option('-s, --secret <secret>', 'Signing secret (>= 32 chars) for JWS attestation')
    .option('--demo', 'Allow synthetic mock tools when target has zero tools (demo mode)')
    .action(async (target, options) => {
      await evidenceCommand(target, options);
    });

  program
    .command('verify')
    .description('Verify an RFC 7515 detached JWS compliance token and inspect audit claims')
    .argument('[token]', 'RFC 7515 JWS token string')
    .option('--jws <token>', 'RFC 7515 JWS token string')
    .option('-f, --file <path>', 'Read JWS token from certificate file')
    .option('-s, --secret <secret>', 'Shared HMAC secret for offline HS256 verification')
    .option('-k, --public-key <key>', 'Public key (PEM, JWK, or path) for ES256 verification')
    .action(async (token, options) => {
      await verifyCommand(token, options);
    });

  program
    .command('lock')
    .description('Generate cryptographic toolveto.lock.json pinning SHA-256 hashes of tool schemas & descriptions')
    .argument('[target]', 'Target MCP server directory or tool manifest', '.')
    .option('-o, --output <path>', 'Output lockfile path')
    .action(async (target, options) => {
      await lockCommand(target, options);
    });

  program
    .command('export-policy')
    .description('Generate AWS Cedar or Open Policy Agent (OPA/Rego) guardrails from MCP tool definitions')
    .argument('[target]', 'Target MCP server directory or tool manifest', '.')
    .option('-f, --format <format>', 'Policy language: cedar or opa', 'cedar')
    .option('-o, --output <path>', 'Output policy file path')
    .action(async (target, options) => {
      await exportPolicyCommand(target, options);
    });

  program
    .command('login')
    .description('Authenticate CLI with ToolVeto Cloud using your license token')
    .argument('[token]', 'Your ToolVeto license token (tv_live_...)')
    .option('--api-url <url>', 'ToolVeto Cloud API URL', 'https://api.toolveto.ai')
    .action(async (token, options) => {
      await loginCommand(token, options);
    });

  return program;
}

export * from './telemetry.js';

