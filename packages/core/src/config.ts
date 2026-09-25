import * as fs from 'node:fs';
import * as path from 'node:path';

export interface ToolvetoConfig {
  version?: number;
  server?: {
    command?: string;
    url?: string;
  };
  sandbox?: {
    image?: string;
    memory?: string;
    timeoutMs?: number;
  };
  destructiveAuthorization?: boolean;
  stateProbe?: {
    readTool?: string;
    keyPath?: string;
  };
}

export function parseSimpleYaml(content: string): Record<string, any> {
  const result: Record<string, any> = {};
  const lines = content.split('\n');
  let currentSection: string | null = null;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    // Check for nested section
    if (line.match(/^[a-zA-Z0-9_-]+:\s*$/)) {
      currentSection = trimmed.replace(':', '');
      result[currentSection] = {};
      continue;
    }

    if (currentSection && line.startsWith('  ')) {
      const match = trimmed.match(/^([a-zA-Z0-9_-]+):\s*(.*)$/);
      if (match) {
        const key = match[1];
        let val: any = match[2].trim();
        if (val === 'true') val = true;
        else if (val === 'false') val = false;
        else if (!isNaN(Number(val)) && val !== '') val = Number(val);
        else if (val.startsWith('"') && val.endsWith('"')) val = val.slice(1, -1);
        else if (val.startsWith("'") && val.endsWith("'")) val = val.slice(1, -1);
        result[currentSection][key] = val;
      }
      continue;
    }

    // Top-level key: value
    const match = trimmed.match(/^([a-zA-Z0-9_-]+):\s*(.*)$/);
    if (match) {
      currentSection = null;
      const key = match[1];
      let val: any = match[2].trim();
      if (val === 'true') val = true;
      else if (val === 'false') val = false;
      else if (!isNaN(Number(val)) && val !== '') val = Number(val);
      else if (val.startsWith('"') && val.endsWith('"')) val = val.slice(1, -1);
      else if (val.startsWith("'") && val.endsWith("'")) val = val.slice(1, -1);
      result[key] = val;
    }
  }

  return result;
}

export function loadToolvetoConfig(targetDir = '.'): ToolvetoConfig {
  const candidates = [
    path.join(targetDir, 'toolveto.yml'),
    path.join(targetDir, 'toolveto.yaml'),
    path.join(process.cwd(), 'toolveto.yml'),
    path.join(process.cwd(), 'toolveto.yaml'),
  ];

  for (const file of candidates) {
    if (fs.existsSync(file)) {
      try {
        const raw = fs.readFileSync(file, 'utf-8');
        return parseSimpleYaml(raw) as ToolvetoConfig;
      } catch {
        // Fall back to empty config if parse error
      }
    }
  }

  return {};
}
