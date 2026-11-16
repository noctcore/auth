/**
 * An in-memory CounterStore with the guarantees the conformance suite asks of
 * real adapters. For unit tests and prototypes only.
 */
import { systemClock, type Clock } from '../../ports/clock';
import type { CounterStore, CounterWindow } from '../../ports/stores';

export class MemoryCounterStore implements CounterStore {
  private readonly counters = new Map<string, { count: number; resetAt: number }>();

  constructor(private readonly clock: Clock = systemClock) {}

  private live(key: string): { count: number; resetAt: number } | null {
    const entry = this.counters.get(key);

    if (!entry) return null;

    if (entry.resetAt <= this.clock.now()) {
      this.counters.delete(key);

      return null;
    }

    return entry;
  }

  async increment(key: string, windowMs: number): Promise<CounterWindow> {
    const entry = this.live(key) ?? { count: 0, resetAt: this.clock.now() + windowMs };

    entry.count += 1;
    this.counters.set(key, entry);

    return { count: entry.count, resetAt: entry.resetAt };
  }

  async get(key: string): Promise<CounterWindow | null> {
    const entry = this.live(key);

    return entry ? { ...entry } : null;
  }

  async set(key: string, count: number, windowMs: number): Promise<void> {
    this.counters.set(key, { count, resetAt: this.clock.now() + windowMs });
  }

  async decrement(key: string): Promise<void> {
    const entry = this.live(key);

    if (entry && entry.count > 0) entry.count -= 1;
  }

  async reset(key: string): Promise<void> {
    this.counters.delete(key);
  }
}
