import * as fs from 'node:fs';
import * as path from 'node:path';

export type GatewayPolicy = 'strict' | 'standard' | 'permissive';

export interface UpstreamRouteConfig {
  name: string;
  url: string;
  pathPrefix?: string;
  toolPrefix?: string;
  policy?: GatewayPolicy;
  authHeader?: string;
}

export interface GatewayYamlConfig {
  version?: string;
  port?: number;
  auth?: {
    type?: 'bearer' | 'passthrough' | 'none';
    secret?: string;
  };
  defaultPolicy?: GatewayPolicy;
  upstreams: Record<string, UpstreamRouteConfig>;
}

export function parseGatewayYaml(content: string): GatewayYamlConfig {
  const config: GatewayYamlConfig = {
    version: '1',
    port: 8080,
    defaultPolicy: 'standard',
    upstreams: {},
  };

  const lines = content.split('\n');
  let currentUpstream: string | null = null;
  let inUpstreamsSection = false;
  let inAuthSection = false;

  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    // Check sections
    if (rawLine.match(/^upstreams:\s*$/)) {
      inUpstreamsSection = true;
      inAuthSection = false;
      continue;
    }
    if (rawLine.match(/^auth:\s*$/)) {
      inAuthSection = true;
      inUpstreamsSection = false;
      config.auth = {};
      continue;
    }

    if (inAuthSection && rawLine.startsWith('  ')) {
      const match = trimmed.match(/^([a-zA-Z0-9_-]+):\s*(.*)$/);
      if (match) {
        const key = match[1];
        let val = match[2].trim().replace(/^['"]|['"]$/g, '');
        // Resolve env vars like ${TOOLVETO_SECRET}
        val = val.replace(/\$\{([^}]+)\}/g, (_, envKey) => process.env[envKey] || '');
        if (config.auth) {
          (config.auth as any)[key] = val;
        }
      }
      continue;
    }

    if (inUpstreamsSection) {
      // New upstream item (e.g. "  stripe:" or "  neon:")
      const upstreamMatch = rawLine.match(/^  ([a-zA-Z0-9_-]+):\s*$/);
      if (upstreamMatch) {
        currentUpstream = upstreamMatch[1];
        config.upstreams[currentUpstream] = {
          name: currentUpstream,
          url: '',
          policy: config.defaultPolicy || 'standard',
        };
        continue;
      }

      // Upstream properties (e.g. "    url: http://..." or "    prefix: /stripe")
      if (currentUpstream && rawLine.startsWith('    ')) {
        const propMatch = trimmed.match(/^([a-zA-Z0-9_-]+):\s*(.*)$/);
        if (propMatch) {
          const key = propMatch[1];
          let val = propMatch[2].trim().replace(/^['"]|['"]$/g, '');
          val = val.replace(/\$\{([^}]+)\}/g, (_, envKey) => process.env[envKey] || '');

          const u = config.upstreams[currentUpstream];
          if (key === 'url') u.url = val;
          else if (key === 'prefix' || key === 'pathPrefix') u.pathPrefix = val;
          else if (key === 'toolPrefix') u.toolPrefix = val;
          else if (key === 'policy') u.policy = val as GatewayPolicy;
          else if (key === 'authHeader') u.authHeader = val;
        }
        continue;
      }
    }

    // Top-level properties
    const topMatch = trimmed.match(/^([a-zA-Z0-9_-]+):\s*(.*)$/);
    if (topMatch) {
      const key = topMatch[1];
      let val = topMatch[2].trim().replace(/^['"]|['"]$/g, '');
      if (key === 'port') config.port = Number(val);
      else if (key === 'policy' || key === 'defaultPolicy') config.defaultPolicy = val as GatewayPolicy;
      else if (key === 'version') config.version = val;
    }
  }

  // Fallback default upstream if none declared
  if (Object.keys(config.upstreams).length === 0) {
    config.upstreams['default'] = {
      name: 'default',
      url: process.env.UPSTREAM_URL || 'http://localhost:3000',
      policy: config.defaultPolicy || 'standard',
    };
  }

  return config;
}

export function loadGatewayConfig(targetDir = '.'): GatewayYamlConfig {
  const candidates = [
    path.join(targetDir, 'toolveto-gateway.yml'),
    path.join(targetDir, 'toolveto-gateway.yaml'),
    path.join(process.cwd(), 'toolveto-gateway.yml'),
    path.join(process.cwd(), 'toolveto-gateway.yaml'),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      try {
        const raw = fs.readFileSync(candidate, 'utf-8');
        return parseGatewayYaml(raw);
      } catch {
        // Fall back to default
      }
    }
  }

  return {
    version: '1',
    port: Number(process.env.PORT) || 8080,
    defaultPolicy: 'standard',
    upstreams: {
      default: {
        name: 'default',
        url: process.env.UPSTREAM_URL || 'http://localhost:3000',
        policy: 'standard',
      },
    },
  };
}
