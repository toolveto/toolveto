import { ShieldStorage, McpCallResponse } from '../index.js';

export interface PostgresClientLike {
  query(sql: string, params?: any[]): Promise<{ rows: any[] }>;
}

export class PostgresShieldStorage implements ShieldStorage {
  private tablesInitialized = false;

  constructor(private client: PostgresClientLike) {}

  private async ensureTables(): Promise<void> {
    if (this.tablesInitialized) return;
    try {
      await this.client.query(`
        CREATE TABLE IF NOT EXISTS toolveto_shield_cache (
          key VARCHAR(255) PRIMARY KEY,
          value TEXT NOT NULL,
          expires_at BIGINT
        );
      `);
      await this.client.query(`
        CREATE TABLE IF NOT EXISTS toolveto_shield_calls (
          key VARCHAR(255) NOT NULL,
          call_timestamp BIGINT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_toolveto_shield_calls_key_time ON toolveto_shield_calls(key, call_timestamp);
      `);
      this.tablesInitialized = true;
    } catch {
      // Allow fallback if tables already exist or permissions are read-only
      this.tablesInitialized = true;
    }
  }

  async get(key: string): Promise<McpCallResponse | undefined> {
    await this.ensureTables();
    const now = Date.now();
    const res = await this.client.query(
      `SELECT value, expires_at FROM toolveto_shield_cache WHERE key = $1`,
      [key]
    );
    if (!res.rows || res.rows.length === 0) return undefined;
    const row = res.rows[0];
    if (row.expires_at && Number(row.expires_at) < now) {
      await this.client.query(`DELETE FROM toolveto_shield_cache WHERE key = $1`, [key]);
      return undefined;
    }
    try {
      return JSON.parse(row.value);
    } catch {
      return undefined;
    }
  }

  async set(key: string, value: McpCallResponse, ttlMs?: number): Promise<void> {
    await this.ensureTables();
    const expiresAt = ttlMs ? Date.now() + ttlMs : null;
    const serialized = JSON.stringify(value);
    await this.client.query(
      `INSERT INTO toolveto_shield_cache (key, value, expires_at)
       VALUES ($1, $2, $3)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at`,
      [key, serialized, expiresAt]
    );
  }

  async recordCall(key: string, timestamp: number, windowMs: number): Promise<number> {
    await this.ensureTables();
    const windowStart = timestamp - windowMs;
    // Insert new call
    await this.client.query(
      `INSERT INTO toolveto_shield_calls (key, call_timestamp) VALUES ($1, $2)`,
      [key, timestamp]
    );
    // Prune expired calls outside the window
    await this.client.query(
      `DELETE FROM toolveto_shield_calls WHERE key = $1 AND call_timestamp < $2`,
      [key, windowStart]
    );
    // Count remaining calls in current sliding window
    const countRes = await this.client.query(
      `SELECT COUNT(*)::int as count FROM toolveto_shield_calls WHERE key = $1`,
      [key]
    );
    return countRes.rows?.[0]?.count ? Number(countRes.rows[0].count) : 1;
  }

  async clear(): Promise<void> {
    await this.ensureTables();
    await this.client.query(`TRUNCATE TABLE toolveto_shield_cache, toolveto_shield_calls`);
  }
}
