import { Command } from 'commander';
import { checkCommand } from './commands/check.js';
import { fixCommand } from './commands/fix.js';
import { proxyCommand } from './commands/proxy.js';
import { badgeCommand } from './commands/badge.js';
import { evidenceCommand } from './commands/evidence.js';
import { loginCommand } from './commands/login.js';

export function createProgram(): Command {
  const program = new Command();

  program
    .name('toolveto')
    .description('Deterministic Chaos Testing, CI Blocking Gates & Auto-Remediation for MCP Servers')
    .version('0.1.0');

  program
    .command('check')
    .description('Run deterministic checks on an MCP server (<90s, $0, zero LLM)')
    .argument('<target>', 'Path to local MCP server directory, binary, or Streamable HTTP URL')
    .option('--with-llm', 'Enable Stage 4 LLM E_heal self-heal judge (requires API key)')
    .option('--json', 'Output machine-readable JSON report')
    .action(async (target, options) => {
      await checkCommand(target, options);
    });

  program
    .command('fix')
    .description('Auto-apply suggested AST code patches for failed checks')
    .argument('[target]', 'Path to schema file or server directory')
    .option('--apply', 'Directly modify local source files')
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
    .option('-s, --score <score>', 'Evaluated score (0-100)', '100')
    .option('-t, --tier <tier>', 'Certification tier (Platinum, Gold, Silver, Bronze, Rejected)')
    .option('-o, --output <path>', 'Output SVG file path', 'toolveto-badge.svg')
    .action(async (options) => {
      await badgeCommand(options);
    });

  program
    .command('evidence')
    .description('Generate an AIUC-1 / OWASP compliant JWS-signed evidence packet for CISO review')
    .option('-f, --format <format>', 'Output format: aiuc1, owasp, json', 'aiuc1')
    .option('-t, --target <path>', 'Target server path or schema file', '.')
    .option('-o, --output <path>', 'Output file destination')
    .action(async (options) => {
      await evidenceCommand(options);
    });

  program
    .command('login')
    .description('Authenticate CLI with ToolVeto Cloud using your license token')
    .argument('[token]', 'Your ToolVeto license token (tv_live_...)')
    .option('--api-url <url>', 'ToolVeto Cloud API URL', 'http://localhost:3001')
    .action(async (token, options) => {
      await loginCommand(token, options);
    });

  return program;
}
