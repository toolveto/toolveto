import { ShieldStorage, McpCallResponse } from '../index.js';

export interface PostgresClientLike {
  query(sql: string, params?: any[]): Promise<{ rows: any[] }>;
  connect?: () => Promise<{
    query(sql: string, params?: any[]): Promise<{ rows: any[] }>;
    release: () => void;
  }>;
}

export interface PostgresShieldStorageOptions {
  vacuumIntervalCalls?: number; // default: 500 (0 disables automatic cleanup)
  statementTimeoutMs?: number; // default: 5000ms (bounded DB query timeout)
}

export interface HardenedShieldPgConfig {
  connectionString: string;
  max: number;
  connectionTimeoutMillis: number;
  statement_timeout: number;
  query_timeout: number;
  idle_in_transaction_session_timeout: number;
}

export function createHardenedShieldPgConfig(
  connectionString: string,
  options: {
    statementTimeoutMs?: number;
    queryTimeoutMs?: number;
    connectionTimeoutMillis?: number;
    max?: number;
  } = {}
): HardenedShieldPgConfig {
  const statementTimeoutMs = Math.max(100, Math.min(options.statementTimeoutMs ?? 5000, 10000));
  const queryTimeoutMs = Math.max(100, Math.min(options.queryTimeoutMs ?? statementTimeoutMs, 10000));
  return {
    connectionString,
    max: options.max ?? 20,
    connectionTimeoutMillis: options.connectionTimeoutMillis ?? 5000,
    statement_timeout: statementTimeoutMs,
    query_timeout: queryTimeoutMs,
    idle_in_transaction_session_timeout: 10000,
  };
}

export class PostgresShieldStorage implements ShieldStorage {
  private tablesInitialized = false;
  private callCounter = 0;
  private vacuumInFlight = false;
  private vacuumIntervalCalls: number;
  private statementTimeoutMs: number;

  constructor(
    private client: PostgresClientLike,
    options: PostgresShieldStorageOptions = {}
  ) {
    this.vacuumIntervalCalls = options.vacuumIntervalCalls ?? 500;
    this.statementTimeoutMs = options.statementTimeoutMs ?? 5000;
  }

  private async runQuery(sql: string, params?: any[]): Promise<{ rows: any[] }> {
    if (this.statementTimeoutMs <= 0) {
      return this.client.query(sql, params);
    }
    // When backed by a pg.Pool (connect() available), enforce server-side SET LOCAL statement_timeout
    // inside a short transaction so timed-out queries abort on Postgres instead of leaking connections.
    if (typeof this.client.connect === 'function') {
      const conn = await this.client.connect();
      try {
        await conn.query('BEGIN');
        await conn.query(`SELECT set_config('statement_timeout', $1, true)`, [`${this.statementTimeoutMs}ms`]);
        const res = await conn.query(sql, params);
        await conn.query('COMMIT');
        return res;
      } catch (err) {
        await conn.query('ROLLBACK').catch(() => undefined);
        throw err;
      } finally {
        conn.release();
      }
    }
    let timer: NodeJS.Timeout | undefined;
    try {
      return await Promise.race([
        this.client.query(sql, params),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => {
            reject(new Error(`[ToolVeto Shield Postgres] Query exceeded ${this.statementTimeoutMs}ms statementTimeoutMs`));
          }, this.statementTimeoutMs);
          timer.unref?.();
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  private async ensureTables(): Promise<void> {
    if (this.tablesInitialized) return;
    try {
      await this.runQuery(`
        CREATE TABLE IF NOT EXISTS toolveto_shield_cache (
          key VARCHAR(255) PRIMARY KEY,
          value TEXT NOT NULL,
          expires_at BIGINT
        );
        CREATE INDEX IF NOT EXISTS idx_toolveto_shield_cache_expires ON toolveto_shield_cache(expires_at);
      `);
      await this.runQuery(`
        CREATE TABLE IF NOT EXISTS toolveto_shield_calls (
          key VARCHAR(255) NOT NULL,
          call_timestamp BIGINT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_toolveto_shield_calls_key_time ON toolveto_shield_calls(key, call_timestamp);
      `);
      await this.runQuery(`
        CREATE TABLE IF NOT EXISTS toolveto_shield_locks (
          key VARCHAR(255) PRIMARY KEY,
          expires_at BIGINT NOT NULL
        );
      `);
      this.tablesInitialized = true;
    } catch (err: any) {
      // Only latch tablesInitialized on permission errors (42501) where tables were pre-provisioned by DBA;
      // transient network/connection errors must retry on next call rather than permanently latching true.
      if (err && (err.code === '42501' || String(err.message || '').toLowerCase().includes('permission denied'))) {
        this.tablesInitialized = true;
      }
    }
  }

  async get(key: string): Promise<McpCallResponse | undefined> {
    await this.ensureTables();
    const now = Date.now();
    const res = await this.runQuery(
      `SELECT value, expires_at FROM toolveto_shield_cache WHERE key = $1`,
      [key]
    );
    if (!res.rows || res.rows.length === 0) return undefined;
    const row = res.rows[0];
    if (row.expires_at && Number(row.expires_at) < now) {
      this.runQuery(`DELETE FROM toolveto_shield_cache WHERE key = $1`, [key]).catch(() => {});
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
    await this.runQuery(
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
    const countRes = await this.runQuery(
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
      this.runQuery(`DELETE FROM toolveto_shield_calls WHERE call_timestamp < $1`, [windowStart])
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
    const res = await this.runQuery(
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
    await this.runQuery(`DELETE FROM toolveto_shield_locks WHERE key = $1`, [key]);
  }

  async clear(): Promise<void> {
    await this.ensureTables();
    await this.runQuery(`TRUNCATE TABLE toolveto_shield_cache, toolveto_shield_calls, toolveto_shield_locks`);
  }
}

export const PostgresIdempotencyStore = PostgresShieldStorage;
