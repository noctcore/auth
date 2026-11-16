/**
 * @noctcore/auth-redis: Redis session and counter stores for @noctcore/auth.
 *
 * Layout (every key under `prefix`, default `auth:`):
 *
 * - `s:<sessionId>`  the session as JSON, with a TTL at its absolute end;
 * - `u:<userId>`     a sorted set of the user's session ids, scored by expiry;
 * - `e:<userId>`     the user's revocation epoch, kept alive past every session;
 * - `c:<key>`        a fixed-window counter, its TTL armed by the first hit.
 *
 * Requires Redis 6.2 or newer (`SET ... XX KEEPTTL`). Multi-key scripts touch a
 * session and its user's index together, so Redis Cluster is not supported;
 * a single primary, with replicas or Sentinel, is.
 */
import type { Clock, CounterStore, CounterWindow, SessionStore, StoredSession } from '@noctcore/auth';
import { AuthConfigError, systemClock, toMilliseconds, type Duration } from '@noctcore/auth';
import type { Redis } from 'ioredis';

export interface RedisStoreOptions {
  /** Key prefix. Default `auth:`. */
  readonly prefix?: string;
  readonly clock?: Clock;
}

export interface RedisSessionStoreOptions extends RedisStoreOptions {
  /**
   * How long an epoch outlives the last write to it. Must exceed the longest
   * session lifetime (remember-me, 30 d by default). Default 90 d. If it ever
   * lapses, the user's sessions fail closed (they are signed out), never open.
   */
  readonly epochTtl?: Duration;
  /**
   * The longest session this store will hold: at least your remember-me TTL
   * (`session.rememberMeTtl`, 30 d by default). The store refuses to start when
   * `epochTtl` is not longer, and `createAuth` refuses a remember-me or
   * absolute TTL longer than this value.
   */
  readonly maxSessionTtl?: Duration;
}

// KEYS[1] session, KEYS[2] user index, KEYS[3] epoch
// ARGV[1] json, ARGV[2] ttl ms, ARGV[3] expiresAt, ARGV[4] id, ARGV[5] now, ARGV[6] epoch ttl ms
const CREATE = `
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
redis.call('ZADD', KEYS[2], ARGV[3], ARGV[4])
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', ARGV[5])
local ttl = tonumber(ARGV[2])
if redis.call('PTTL', KEYS[2]) < ttl then redis.call('PEXPIRE', KEYS[2], ttl) end
local ettl = tonumber(ARGV[6])
if redis.call('EXISTS', KEYS[3]) == 1 and redis.call('PTTL', KEYS[3]) < ettl then redis.call('PEXPIRE', KEYS[3], ettl) end
return 1
`;

// KEYS[1] epoch; ARGV[1] epoch ttl ms
const BUMP = `
local epoch = redis.call('INCR', KEYS[1])
redis.call('PEXPIRE', KEYS[1], ARGV[1])
return epoch
`;

// KEYS[1] counter; ARGV[1] window ms
const INCREMENT = `
local count = redis.call('INCR', KEYS[1])
local ttl = redis.call('PTTL', KEYS[1])
if count == 1 or ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return {count, ttl}
`;

/** The `SessionStore` on Redis. */
// KEYS[1] counter. DECR keeps the TTL; never below 0, never creates the key.
const DECREMENT = `
local v = tonumber(redis.call('GET', KEYS[1]))
if v and v > 0 then redis.call('DECR', KEYS[1]) end
return 0
`;

export class RedisSessionStore implements SessionStore {
  private readonly prefix: string;
  private readonly clock: Clock;
  private readonly epochTtlMs: number;
  /** The longest session this store guards; `createAuth` refuses a longer remember-me TTL. */
  readonly maxSessionTtlMs: number;

  constructor(
    private readonly redis: Redis,
    options: RedisSessionStoreOptions = {},
  ) {
    this.prefix = options.prefix ?? 'auth:';
    this.clock = options.clock ?? systemClock;
    this.epochTtlMs = toMilliseconds(options.epochTtl ?? '90d');
    this.maxSessionTtlMs = toMilliseconds(options.maxSessionTtl ?? '30d');
    if (this.epochTtlMs <= this.maxSessionTtlMs) {
      throw new AuthConfigError('epochTtl must be longer than the longest session (maxSessionTtl, your remember-me TTL)');
    }
  }

  private sessionKey(id: string): string {
    return `${this.prefix}s:${id}`;
  }

  private userKey(userId: string): string {
    return `${this.prefix}u:${userId}`;
  }

  private epochKey(userId: string): string {
    return `${this.prefix}e:${userId}`;
  }

  async create(session: StoredSession, ttlMs: number): Promise<void> {
    if (ttlMs > this.epochTtlMs) {
      throw new AuthConfigError('A session may not outlive its revocation epoch: raise epochTtl above the remember-me TTL');
    }
    await this.redis.eval(
      CREATE,
      3,
      this.sessionKey(session.id),
      this.userKey(session.userId),
      this.epochKey(session.userId),
      JSON.stringify(session),
      String(Math.max(1, Math.ceil(ttlMs))),
      String(session.expiresAt),
      session.id,
      String(this.clock.now()),
      String(this.epochTtlMs),
    );
  }

  async get(id: string): Promise<StoredSession | null> {
    return parse(await this.redis.get(this.sessionKey(id)));
  }

  async touch(session: StoredSession): Promise<boolean> {
    // XX: only if it still exists; KEEPTTL: the absolute end never moves.
    const result = await this.redis.set(this.sessionKey(session.id), JSON.stringify(session), 'KEEPTTL', 'XX');
    return result === 'OK';
  }

  async delete(userId: string, ids: readonly string[]): Promise<void> {
    if (ids.length === 0) return;
    const results = await this.redis
      .multi()
      .del(...ids.map((id) => this.sessionKey(id)))
      .zrem(this.userKey(userId), ...ids)
      .exec();
    const failure = results?.find(([error]) => error)?.[0];
    if (failure) throw failure;
  }

  async listByUser(userId: string): Promise<StoredSession[]> {
    const key = this.userKey(userId);
    const now = this.clock.now();
    await this.redis.zremrangebyscore(key, '-inf', String(now));
    const ids = await this.redis.zrange(key, '0', '-1');
    if (ids.length === 0) return [];
    const values = await this.redis.mget(...ids.map((id) => this.sessionKey(id)));
    const sessions: StoredSession[] = [];
    const gone: string[] = [];
    values.forEach((value, index) => {
      const session = parse(value);
      if (session) sessions.push(session);
      else gone.push(ids[index] as string);
    });
    if (gone.length > 0) await this.redis.zrem(key, ...gone);
    return sessions;
  }

  async getEpoch(userId: string): Promise<number> {
    const value = await this.redis.get(this.epochKey(userId));
    return value === null ? 0 : Number(value);
  }

  /** Remaining TTL of the user's epoch in ms (-2 when absent). */
  async epochTtlRemaining(userId: string): Promise<number> {
    return this.redis.pttl(this.epochKey(userId));
  }

  async bumpEpoch(userId: string): Promise<number> {
    return Number(await this.redis.eval(BUMP, 1, this.epochKey(userId), String(this.epochTtlMs)));
  }
}

/** The `CounterStore` on Redis: one INCR per hit, the TTL armed atomically by the first. */
export class RedisCounterStore implements CounterStore {
  private readonly prefix: string;
  private readonly clock: Clock;

  constructor(
    private readonly redis: Redis,
    options: RedisStoreOptions = {},
  ) {
    this.prefix = options.prefix ?? 'auth:';
    this.clock = options.clock ?? systemClock;
  }

  private key(key: string): string {
    return `${this.prefix}c:${key}`;
  }

  async increment(key: string, windowMs: number): Promise<CounterWindow> {
    const [count, ttl] = (await this.redis.eval(INCREMENT, 1, this.key(key), String(Math.max(1, Math.ceil(windowMs))))) as [number, number];
    return { count: Number(count), resetAt: this.clock.now() + Number(ttl) };
  }

  async get(key: string): Promise<CounterWindow | null> {
    const [[, count], [, ttl]] = (await this.redis.multi().get(this.key(key)).pttl(this.key(key)).exec()) as [
      [Error | null, string | null],
      [Error | null, number],
    ];
    if (count === null || ttl < 0) return null;
    return { count: Number(count), resetAt: this.clock.now() + ttl };
  }

  async set(key: string, count: number, windowMs: number): Promise<void> {
    await this.redis.set(this.key(key), String(count), 'PX', Math.max(1, Math.ceil(windowMs)));
  }

  async decrement(key: string): Promise<void> {
    await this.redis.eval(DECREMENT, 1, this.key(key));
  }

  async reset(key: string): Promise<void> {
    await this.redis.del(this.key(key));
  }
}

/** Both Redis stores on one client. */
export function redisStores(redis: Redis, options: RedisSessionStoreOptions = {}) {
  return { sessions: new RedisSessionStore(redis, options), counters: new RedisCounterStore(redis, options) };
}

function parse(value: string | null): StoredSession | null {
  if (value === null) return null;
  try {
    return JSON.parse(value) as StoredSession;
  } catch {
    return null;
  }
}
