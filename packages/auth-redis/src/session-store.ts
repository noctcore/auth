/**
 * Sessions on Redis: each session a JSON value with a TTL at its absolute end,
 * a per-user sorted set of session ids, and a per-user revocation epoch that
 * outlives every session.
 */
import type { RedisSessionStoreOptions } from './options';
import { BUMP, CREATE } from './scripts';
import type { Clock, SessionStore, StoredSession } from '@noctcore/auth';
import { AuthConfigError, systemClock, toMilliseconds } from '@noctcore/auth';
import type { Redis } from 'ioredis';

/** The `SessionStore` on Redis. */
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
      throw new AuthConfigError(
        'epochTtl must be longer than the longest session (maxSessionTtl, your remember-me TTL)',
      );
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
      throw new AuthConfigError(
        'A session may not outlive its revocation epoch: raise epochTtl above the remember-me TTL',
      );
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
    const result = await this.redis.set(
      this.sessionKey(session.id),
      JSON.stringify(session),
      'KEEPTTL',
      'XX',
    );

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

function parse(value: string | null): StoredSession | null {
  if (value === null) return null;

  try {
    return JSON.parse(value) as StoredSession;
  } catch {
    return null;
  }
}
