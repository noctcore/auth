import type { DatabaseSync } from 'node:sqlite';
import { systemClock, type Clock, type CounterStore, type CounterWindow } from '@noctcore/auth';

interface Row {
  readonly count: number;
  readonly reset_at: number;
}

/**
 * A CounterStore on node:sqlite, for a single-process app. Each method is one
 * statement, and SQLite runs one statement at a time, so concurrent calls
 * cannot interleave. An expired row counts as missing and is replaced on the
 * next hit.
 */
export class SqliteCounterStore implements CounterStore {
  readonly #db: DatabaseSync;
  readonly #clock: Clock;

  constructor(db: DatabaseSync, clock: Clock = systemClock) {
    this.#db = db;
    this.#clock = clock;

    db.exec(`CREATE TABLE IF NOT EXISTS auth_counters (
      key TEXT PRIMARY KEY,
      count INTEGER NOT NULL,
      reset_at INTEGER NOT NULL
    )`);
  }

  async increment(key: string, windowMs: number): Promise<CounterWindow> {
    const now = this.#clock.now();

    // The first hit, or the first after the window ended, starts a new window.
    // Later hits only add one: the window end never moves.
    const row = this.#db
      .prepare(
        `INSERT INTO auth_counters (key, count, reset_at) VALUES (?, 1, ?)
         ON CONFLICT (key) DO UPDATE SET
           count = CASE WHEN reset_at <= ? THEN 1 ELSE count + 1 END,
           reset_at = CASE WHEN reset_at <= ? THEN excluded.reset_at ELSE reset_at END
         RETURNING count, reset_at`,
      )
      .get(key, now + windowMs, now, now) as unknown as Row;

    return { count: row.count, resetAt: row.reset_at };
  }

  async get(key: string): Promise<CounterWindow | null> {
    const row = this.#db
      .prepare('SELECT count, reset_at FROM auth_counters WHERE key = ? AND reset_at > ?')
      .get(key, this.#clock.now()) as unknown as Row | undefined;

    return row ? { count: row.count, resetAt: row.reset_at } : null;
  }

  async set(key: string, count: number, windowMs: number): Promise<void> {
    this.#db
      .prepare('INSERT OR REPLACE INTO auth_counters (key, count, reset_at) VALUES (?, ?, ?)')
      .run(key, count, this.#clock.now() + windowMs);
  }

  async decrement(key: string): Promise<void> {
    // Only a live row is touched, so a missing key stays missing and the TTL stays.
    this.#db
      .prepare('UPDATE auth_counters SET count = MAX(count - 1, 0) WHERE key = ? AND reset_at > ?')
      .run(key, this.#clock.now());
  }

  async reset(key: string): Promise<void> {
    this.#db.prepare('DELETE FROM auth_counters WHERE key = ?').run(key);
  }
}
