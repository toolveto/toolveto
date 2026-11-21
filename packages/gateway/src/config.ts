import * as fs from 'node:fs';
import * as path from 'node:path';
import { parse as parseYaml } from 'yaml';
import type { ToolShieldOverride, ShieldPolicyOptions } from '@toolveto/shield';
import type { OrgCatalogPolicyDocument } from '@toolveto/core';

export type GatewayPolicy = 'strict' | 'standard' | 'permissive';

export interface GatewayCloudConfig {
  apiUrl?: string;
  licenseKey?: string;
  customerId?: string;
  repo?: string;
  syncTraces?: boolean;
  syncDrift?: boolean;
}

export interface UpstreamRouteConfig {
  name: string;
  url: string;
  pathPrefix?: string;
  toolPrefix?: string;
  policy?: GatewayPolicy;
  authHeader?: string;
  timeoutMs?: number;
  allowLocal?: boolean;
  tokenBudget?: number;
  loopLimit?: { count: number; windowMs: number };
  toolOverrides?: Record<string, ToolShieldOverride>;
  blockedTools?: string[];
  requireDryRunForDestructive?: boolean;
  elicitOnDestructive?: boolean;
  maxLimit?: number;
  trustClientMeta?: boolean;
  shieldPolicy?: ShieldPolicyOptions;
  lockfilePath?: string;
  lockfileHashes?: Record<string, string>;
  tools?: Array<string | { name: string }>;
}

export interface GatewayYamlConfig {
  version?: string;
  port?: number;
  auth?: {
    type?: 'bearer' | 'passthrough' | 'none';
    secret?: string;
    previousSecret?: string;
  };
  defaultPolicy?: GatewayPolicy;
  allowLocal?: boolean;
  tokenBudget?: number;
  loopLimit?: { count: number; windowMs: number };
  toolOverrides?: Record<string, ToolShieldOverride>;
  blockedTools?: string[];
  requireDryRunForDestructive?: boolean;
  elicitOnDestructive?: boolean;
  maxLimit?: number;
  trustClientMeta?: boolean;
  shieldPolicy?: ShieldPolicyOptions;
  lockfilePath?: string;
  lockfileHashes?: Record<string, string>;
  catalogPolicy?: OrgCatalogPolicyDocument;
  catalogPolicyFile?: string;
  cloud?: GatewayCloudConfig;
  upstreams: Record<string, UpstreamRouteConfig>;
}

const ALLOWED_CONFIG_ENV_PREFIXES = ['TOOLVETO_', 'GATEWAY_', 'UPSTREAM_', 'MCP_'];
const ALLOWED_CONFIG_ENV_NAMES = new Set(['PORT', 'NODE_ENV', 'STRIPE_API_KEY', 'NEON_API_KEY', 'GITHUB_TOKEN']);
const UNSAFE_OBJECT_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function isAllowedConfigEnvKey(key: string): boolean {
  const normalized = key.trim();
  if (ALLOWED_CONFIG_ENV_NAMES.has(normalized)) return true;
  return ALLOWED_CONFIG_ENV_PREFIXES.some((prefix) => normalized.startsWith(prefix));
}

function expandEnvPlaceholders(value: any): any {
  if (typeof value === 'string') {
    return value.replace(/\$\{([^}:]+)(?::-?([^}]*))?\}/g, (_, key, fallback) => {
      const normalizedKey = String(key).trim();
      if (!isAllowedConfigEnvKey(normalizedKey)) {
        throw new Error(
          `[ToolVeto Gateway] Disallowed environment variable placeholder "${normalizedKey}" in gateway config`
        );
      }
      const envVal = process.env[normalizedKey];
      return envVal !== undefined && envVal !== '' ? envVal : (fallback ?? '');
    });
  }
  if (Array.isArray(value)) {
    return value.map((item) => expandEnvPlaceholders(item));
  }
  if (value && typeof value === 'object') {
    const out: Record<string, any> = {};
    for (const [k, v] of Object.entries(value)) {
      if (UNSAFE_OBJECT_KEYS.has(k)) continue;
      Object.defineProperty(out, k, {
        value: expandEnvPlaceholders(v),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    return out;
  }
  return value;
}

export function loadLockfileHashesFromDisk(lockfilePath?: string): Record<string, string> | undefined {
  if (!lockfilePath) return undefined;
  const resolved = path.resolve(lockfilePath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`[ToolVeto Gateway] Configured lockfile not found at '${resolved}'`);
  }
  const parsed = JSON.parse(fs.readFileSync(resolved, 'utf-8'));
  const hashes: Record<string, string> = {};
  if (parsed?.tools && typeof parsed.tools === 'object') {
    for (const [toolName, meta] of Object.entries(parsed.tools as Record<string, any>)) {
      if (typeof meta === 'string') {
        hashes[toolName] = meta;
      } else if (meta && typeof meta.sha256 === 'string') {
        hashes[toolName] = meta.sha256;
      }
    }
  }
  return Object.keys(hashes).length > 0 ? hashes : undefined;
}

export function parseGatewayYaml(content: string): GatewayYamlConfig {
  const parsed = parseYaml(content, { maxAliasCount: 32 });
  const rawParsed = expandEnvPlaceholders(parsed || {});
  const defaultPolicy: GatewayPolicy =
    (rawParsed.defaultPolicy || rawParsed.policy || 'standard') as GatewayPolicy;
  const topAllowLocal =
    rawParsed.allowLocal !== undefined ? Boolean(rawParsed.allowLocal) : undefined;

  const config: GatewayYamlConfig = {
    version: rawParsed.version !== undefined ? String(rawParsed.version) : '1',
    port: rawParsed.port !== undefined ? Number(rawParsed.port) : 8080,
    defaultPolicy,
    allowLocal: topAllowLocal,
    tokenBudget: rawParsed.tokenBudget !== undefined ? Number(rawParsed.tokenBudget) : undefined,
    loopLimit:
      rawParsed.loopLimit && typeof rawParsed.loopLimit === 'object'
        ? {
            count: Number(rawParsed.loopLimit.count ?? 5),
            windowMs: Number(rawParsed.loopLimit.windowMs ?? 30000),
          }
        : undefined,
    toolOverrides:
      rawParsed.toolOverrides && typeof rawParsed.toolOverrides === 'object'
        ? rawParsed.toolOverrides
        : undefined,
    blockedTools: Array.isArray(rawParsed.blockedTools)
      ? rawParsed.blockedTools.map(String)
      : undefined,
    requireDryRunForDestructive:
      rawParsed.requireDryRunForDestructive !== undefined
        ? Boolean(rawParsed.requireDryRunForDestructive)
        : undefined,
    elicitOnDestructive:
      rawParsed.elicitOnDestructive !== undefined
        ? Boolean(rawParsed.elicitOnDestructive)
        : undefined,
    maxLimit:
      rawParsed.maxLimit !== undefined ? Number(rawParsed.maxLimit) : undefined,
    trustClientMeta:
      rawParsed.trustClientMeta !== undefined ? Boolean(rawParsed.trustClientMeta) : undefined,
    shieldPolicy:
      rawParsed.shieldPolicy && typeof rawParsed.shieldPolicy === 'object'
        ? rawParsed.shieldPolicy
        : undefined,
    lockfilePath: rawParsed.lockfilePath ? String(rawParsed.lockfilePath) : undefined,
    lockfileHashes:
      rawParsed.lockfileHashes && typeof rawParsed.lockfileHashes === 'object'
        ? rawParsed.lockfileHashes
        : undefined,
    upstreams: {},
  };

  if (rawParsed.auth && typeof rawParsed.auth === 'object') {
    config.auth = {
      type: rawParsed.auth.type,
      secret: rawParsed.auth.secret !== undefined ? String(rawParsed.auth.secret) : undefined,
      previousSecret:
        rawParsed.auth.previousSecret !== undefined
          ? String(rawParsed.auth.previousSecret)
          : undefined,
    };
  }

  if (rawParsed.cloud && typeof rawParsed.cloud === 'object') {
    config.cloud = {
      apiUrl: rawParsed.cloud.apiUrl ? String(rawParsed.cloud.apiUrl) : undefined,
      licenseKey: rawParsed.cloud.licenseKey ? String(rawParsed.cloud.licenseKey) : undefined,
      customerId: rawParsed.cloud.customerId ? String(rawParsed.cloud.customerId) : undefined,
      repo: rawParsed.cloud.repo ? String(rawParsed.cloud.repo) : undefined,
      syncTraces: rawParsed.cloud.syncTraces !== false,
      syncDrift: rawParsed.cloud.syncDrift !== false,
    };
  }

  if (rawParsed.upstreams && typeof rawParsed.upstreams === 'object') {
    for (const [name, rawUp] of Object.entries(rawParsed.upstreams as Record<string, any>)) {
      if (!rawUp || typeof rawUp !== 'object') continue;
      config.upstreams[name] = {
        name,
        url: rawUp.url ? String(rawUp.url) : '',
        pathPrefix: rawUp.pathPrefix || rawUp.prefix ? String(rawUp.pathPrefix || rawUp.prefix) : undefined,
        toolPrefix: rawUp.toolPrefix ? String(rawUp.toolPrefix) : undefined,
        policy: (rawUp.policy || defaultPolicy) as GatewayPolicy,
        authHeader: rawUp.authHeader ? String(rawUp.authHeader) : undefined,
        timeoutMs:
          rawUp.timeoutMs !== undefined || rawUp.timeout !== undefined
            ? Number(rawUp.timeoutMs ?? rawUp.timeout)
            : undefined,
        allowLocal:
          rawUp.allowLocal !== undefined ? Boolean(rawUp.allowLocal) : topAllowLocal,
        tokenBudget: rawUp.tokenBudget !== undefined ? Number(rawUp.tokenBudget) : undefined,
        loopLimit:
          rawUp.loopLimit && typeof rawUp.loopLimit === 'object'
            ? {
                count: Number(rawUp.loopLimit.count ?? 5),
                windowMs: Number(rawUp.loopLimit.windowMs ?? 30000),
              }
            : undefined,
        toolOverrides:
          rawUp.toolOverrides && typeof rawUp.toolOverrides === 'object'
            ? rawUp.toolOverrides
            : undefined,
        blockedTools: Array.isArray(rawUp.blockedTools)
          ? rawUp.blockedTools.map(String)
          : undefined,
        requireDryRunForDestructive:
          rawUp.requireDryRunForDestructive !== undefined
            ? Boolean(rawUp.requireDryRunForDestructive)
            : undefined,
        elicitOnDestructive:
          rawUp.elicitOnDestructive !== undefined
            ? Boolean(rawUp.elicitOnDestructive)
            : undefined,
        maxLimit:
          rawUp.maxLimit !== undefined ? Number(rawUp.maxLimit) : undefined,
        trustClientMeta:
          rawUp.trustClientMeta !== undefined ? Boolean(rawUp.trustClientMeta) : undefined,
        shieldPolicy:
          rawUp.shieldPolicy && typeof rawUp.shieldPolicy === 'object'
            ? rawUp.shieldPolicy
            : undefined,
        lockfilePath: rawUp.lockfilePath ? String(rawUp.lockfilePath) : undefined,
        lockfileHashes:
          rawUp.lockfileHashes && typeof rawUp.lockfileHashes === 'object'
            ? rawUp.lockfileHashes
            : undefined,
        tools: Array.isArray(rawUp.tools) ? rawUp.tools : undefined,
      };
    }
  }

  if (Object.keys(config.upstreams).length === 0) {
    config.upstreams['default'] = {
      name: 'default',
      url: process.env.UPSTREAM_URL || 'http://localhost:3000',
      policy: config.defaultPolicy || 'standard',
      allowLocal: config.allowLocal,
    };
  }

  return config;
}

export const parseGatewayConfig = parseGatewayYaml;

export function loadGatewayConfig(targetDir = '.'): GatewayYamlConfig {
  const candidates = [
    path.join(targetDir, 'toolveto-gateway.yml'),
    path.join(targetDir, 'toolveto-gateway.yaml'),
    path.join(process.cwd(), 'toolveto-gateway.yml'),
    path.join(process.cwd(), 'toolveto-gateway.yaml'),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      const raw = fs.readFileSync(candidate, 'utf-8');
      return parseGatewayYaml(raw);
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
        allowLocal: process.env.TOOLVETO_ALLOW_LOCAL_UPSTREAMS === 'true',
      },
    },
  };
}
