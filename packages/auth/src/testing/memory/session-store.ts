/**
 * An in-memory SessionStore with the guarantees the conformance suite asks of
 * real adapters. For unit tests and prototypes only.
 */
import { systemClock, type Clock } from '../../ports/clock';
import type { SessionStore, StoredSession } from '../../ports/stores';

export class MemorySessionStore implements SessionStore {
  private readonly sessions = new Map<string, { session: StoredSession; expiresAt: number }>();
  private readonly byUser = new Map<string, Set<string>>();
  private readonly epochs = new Map<string, number>();

  constructor(private readonly clock: Clock = systemClock) {}

  private read(id: string): StoredSession | null {
    const entry = this.sessions.get(id);

    if (!entry) return null;

    if (entry.expiresAt <= this.clock.now()) {
      this.sessions.delete(id);

      return null;
    }

    return entry.session;
  }

  async create(session: StoredSession, ttlMs: number): Promise<void> {
    this.sessions.set(session.id, {
      session: structuredClone(session),
      expiresAt: this.clock.now() + ttlMs,
    });

    let ids = this.byUser.get(session.userId);

    if (!ids) this.byUser.set(session.userId, (ids = new Set()));

    ids.add(session.id);
  }

  async get(id: string): Promise<StoredSession | null> {
    const session = this.read(id);

    return session ? structuredClone(session) : null;
  }

  async touch(session: StoredSession): Promise<boolean> {
    const entry = this.sessions.get(session.id);

    if (!entry || !this.read(session.id)) return false;

    entry.session = structuredClone(session);

    return true;
  }

  async delete(userId: string, ids: readonly string[]): Promise<string[]> {
    const index = this.byUser.get(userId);
    const removed: string[] = [];

    for (const id of new Set(ids)) {
      // An entry past its TTL is already gone for every reader.
      if (this.read(id)) removed.push(id);

      this.sessions.delete(id);
      index?.delete(id);
    }

    return removed;
  }

  async listByUser(userId: string): Promise<StoredSession[]> {
    const index = this.byUser.get(userId);

    if (!index) return [];

    const live: StoredSession[] = [];

    for (const id of [...index]) {
      const session = this.read(id);

      if (session) live.push(structuredClone(session));
      else index.delete(id);
    }

    return live;
  }

  async getEpoch(userId: string): Promise<number> {
    return this.epochs.get(userId) ?? 0;
  }

  async bumpEpoch(userId: string): Promise<number> {
    const next = (this.epochs.get(userId) ?? 0) + 1;

    this.epochs.set(userId, next);

    return next;
  }
}
