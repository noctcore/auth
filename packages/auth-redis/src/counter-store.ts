/**
 * Fixed-window counters on Redis, for rate limits and the login lockout.
 */
import type { RedisStoreOptions } from './options';
import { DECREMENT, INCREMENT } from './scripts';
import type { Clock, CounterStore, CounterWindow } from '@noctcore/auth';
import { systemClock } from '@noctcore/auth';
import type { Redis } from 'ioredis';

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
    const [count, ttl] = (await this.redis.eval(
      INCREMENT,
      1,
      this.key(key),
      String(Math.max(1, Math.ceil(windowMs))),
    )) as [number, number];

    return { count: Number(count), resetAt: this.clock.now() + Number(ttl) };
  }

  async get(key: string): Promise<CounterWindow | null> {
    const [[, count], [, ttl]] = (await this.redis
      .multi()
      .get(this.key(key))
      .pttl(this.key(key))
      .exec()) as [[Error | null, string | null], [Error | null, number]];

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
