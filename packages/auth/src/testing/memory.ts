/**
 * In-memory stores with the same guarantees the conformance suite asks of real
 * adapters (they pass it, see tests/conformance.test.ts). For unit tests and
 * prototypes only: nothing survives a restart and nothing is shared between
 * processes.
 */
import { systemClock, type Clock } from '../clock';
import type { NormalizedEmail } from '../email';
import type {
  AuthUser,
  CounterStore,
  CounterWindow,
  SessionStore,
  StoredSession,
  StoredToken,
  TokenStore,
  UserStore,
  WithPasswordHash,
} from '../stores';

interface UserRecord {
  id: string;
  email: string;
  emailVerified: boolean;
  passwordHash: string | null;
  deletedAt: number | null;
}

export class MemoryUserStore implements UserStore<AuthUser> {
  private readonly byId = new Map<string, UserRecord>();
  private sequence = 0;

  constructor(private readonly clock: Clock = systemClock) {}

  private view(record: UserRecord): AuthUser {
    return { id: record.id, email: record.email, emailVerified: record.emailVerified };
  }

  private live(record: UserRecord | undefined): record is UserRecord {
    return record !== undefined && record.deletedAt === null;
  }

  async findCredentialByEmail(email: NormalizedEmail): Promise<WithPasswordHash<AuthUser> | null> {
    for (const record of this.byId.values()) {
      if (record.email === email && this.live(record)) return { ...this.view(record), passwordHash: record.passwordHash };
    }
    return null;
  }

  async findCredentialById(id: string): Promise<WithPasswordHash<AuthUser> | null> {
    const record = this.byId.get(id);
    return this.live(record) ? { ...this.view(record), passwordHash: record.passwordHash } : null;
  }

  async findById(id: string): Promise<AuthUser | null> {
    const record = this.byId.get(id);
    return this.live(record) ? this.view(record) : null;
  }

  async create(input: { email: NormalizedEmail; passwordHash: string }): Promise<AuthUser | null> {
    // Unique on email across soft-deleted rows too, like a database constraint.
    for (const record of this.byId.values()) if (record.email === input.email) return null;
    const record: UserRecord = {
      id: `user_${++this.sequence}`,
      email: input.email,
      emailVerified: false,
      passwordHash: input.passwordHash,
      deletedAt: null,
    };
    this.byId.set(record.id, record);
    return this.view(record);
  }

  async setPasswordHash(id: string, passwordHash: string, options: { readonly expected?: string | null } = {}): Promise<boolean> {
    const record = this.byId.get(id);
    if (!this.live(record)) return false;
    if (options.expected !== undefined && record.passwordHash !== options.expected) return false;
    record.passwordHash = passwordHash;
    return true;
  }

  async markEmailVerified(id: string, email: NormalizedEmail): Promise<boolean> {
    const record = this.byId.get(id);
    if (!this.live(record) || record.email !== email) return false;
    record.emailVerified = true;
    return true;
  }

  /** Test helper: soft-delete a user. */
  async softDelete(id: string): Promise<void> {
    const record = this.byId.get(id);
    if (record) record.deletedAt = this.clock.now();
  }

  /** Test helper: change a user's email (as an email change flow would). */
  async setEmail(id: string, email: NormalizedEmail): Promise<void> {
    const record = this.byId.get(id);
    if (record) {
      record.email = email;
      record.emailVerified = false;
    }
  }

  /** Test helper: give a user no password (a social-only account). */
  async clearPassword(id: string): Promise<void> {
    const record = this.byId.get(id);
    if (record) record.passwordHash = null;
  }
}

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
    this.sessions.set(session.id, { session: structuredClone(session), expiresAt: this.clock.now() + ttlMs });
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

  async delete(userId: string, ids: readonly string[]): Promise<void> {
    const index = this.byUser.get(userId);
    for (const id of ids) {
      this.sessions.delete(id);
      index?.delete(id);
    }
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

export class MemoryTokenStore implements TokenStore {
  private readonly tokens = new Map<string, StoredToken>();

  private key(purpose: string, hash: string): string {
    return `${purpose}\u0000${hash}`;
  }

  async put(token: StoredToken): Promise<void> {
    // No await between the delete and the set: the replacement must be atomic.
    this.removeByUser(token.userId, [token.purpose]);
    this.tokens.set(this.key(token.purpose, token.hash), { ...token, data: { ...token.data } });
  }

  async find(purpose: string, hash: string): Promise<StoredToken | null> {
    const token = this.tokens.get(this.key(purpose, hash));
    return token ? { ...token } : null;
  }

  async findByUser(purpose: string, userId: string): Promise<StoredToken | null> {
    for (const token of this.tokens.values()) {
      if (token.purpose === purpose && token.userId === userId) return { ...token };
    }
    return null;
  }

  async consume(purpose: string, hash: string): Promise<StoredToken | null> {
    const key = this.key(purpose, hash);
    const token = this.tokens.get(key);
    if (!token) return null;
    this.tokens.delete(key);
    return token;
  }

  async incrementAttempts(purpose: string, userId: string, max: number): Promise<number | null> {
    for (const [key, token] of this.tokens) {
      if (token.purpose === purpose && token.userId === userId) {
        if (token.attempts >= max) return null;
        const attempts = token.attempts + 1;
        this.tokens.set(key, { ...token, attempts });
        return attempts;
      }
    }
    return null;
  }

  async deleteByUser(userId: string, purposes?: readonly string[]): Promise<void> {
    this.removeByUser(userId, purposes);
  }

  private removeByUser(userId: string, purposes?: readonly string[]): void {
    for (const [key, token] of this.tokens) {
      if (token.userId === userId && (!purposes || purposes.includes(token.purpose))) this.tokens.delete(key);
    }
  }
}

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

export interface MemoryStores {
  readonly users: MemoryUserStore;
  readonly sessions: MemorySessionStore;
  readonly tokens: MemoryTokenStore;
  readonly counters: MemoryCounterStore;
}

export function memoryStores(clock: Clock = systemClock): MemoryStores {
  return {
    users: new MemoryUserStore(clock),
    sessions: new MemorySessionStore(clock),
    tokens: new MemoryTokenStore(),
    counters: new MemoryCounterStore(clock),
  };
}
