import { ShieldStorage, McpCallResponse } from '../index.js';

export interface PostgresClientLike {
  query(sql: string, params?: any[]): Promise<{ rows: any[] }>;
}

export interface PostgresShieldStorageOptions {
  vacuumIntervalCalls?: number; // default: 500 (0 disables automatic cleanup)
}

export class PostgresShieldStorage implements ShieldStorage {
  private tablesInitialized = false;
  private callCounter = 0;
  private vacuumInFlight = false;
  private vacuumIntervalCalls: number;

  constructor(
    private client: PostgresClientLike,
    options: PostgresShieldStorageOptions = {}
  ) {
    this.vacuumIntervalCalls = options.vacuumIntervalCalls ?? 500;
  }

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
      await this.client.query(`
        CREATE TABLE IF NOT EXISTS toolveto_shield_locks (
          key VARCHAR(255) PRIMARY KEY,
          expires_at BIGINT NOT NULL
        );
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
      this.client.query(`DELETE FROM toolveto_shield_cache WHERE key = $1`, [key]).catch(() => {});
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

    // Single-RTT CTE combining INSERT and sliding-window COUNT(*)
    const countRes = await this.client.query(
      `WITH inserted AS (
         INSERT INTO toolveto_shield_calls (key, call_timestamp) VALUES ($1, $2)
       )
       SELECT COUNT(*)::int + 1 as count FROM toolveto_shield_calls WHERE key = $1 AND call_timestamp >= $3`,
      [key, timestamp, windowStart]
    );

    // Deterministic non-blocking background purge every N calls instead of 10% random vacuum
    this.callCounter++;
    if (
      this.vacuumIntervalCalls > 0 &&
      this.callCounter >= this.vacuumIntervalCalls &&
      !this.vacuumInFlight
    ) {
      this.callCounter = 0;
      this.vacuumInFlight = true;
      this.client
        .query(`DELETE FROM toolveto_shield_calls WHERE call_timestamp < $1`, [windowStart])
        .catch(() => {})
        .finally(() => {
          this.vacuumInFlight = false;
        });
    }

    return countRes.rows?.[0]?.count ? Number(countRes.rows[0].count) : 1;
  }

  async acquireLock(key: string, ttlMs = 30000): Promise<boolean> {
    await this.ensureTables();
    const now = Date.now();
    const expiresAt = now + ttlMs;
    const res = await this.client.query(
      `INSERT INTO toolveto_shield_locks (key, expires_at)
       VALUES ($1, $2)
       ON CONFLICT (key) DO UPDATE SET expires_at = EXCLUDED.expires_at
       WHERE toolveto_shield_locks.expires_at < $3
       RETURNING key`,
      [key, expiresAt, now]
    );
    return Boolean(res.rows && res.rows.length > 0);
  }

  async releaseLock(key: string): Promise<void> {
    await this.ensureTables();
    await this.client.query(`DELETE FROM toolveto_shield_locks WHERE key = $1`, [key]);
  }

  async clear(): Promise<void> {
    await this.ensureTables();
    await this.client.query(`TRUNCATE TABLE toolveto_shield_cache, toolveto_shield_calls, toolveto_shield_locks`);
  }
}

export const PostgresIdempotencyStore = PostgresShieldStorage;
