/**
 * An in-memory UserStore with the guarantees the conformance suite asks of real
 * adapters. For unit tests and prototypes only.
 */
import { systemClock, type Clock } from '../../ports/clock';
import type { NormalizedEmail } from '../../shared/email';
import type { AuthUser, UserStore, WithPasswordHash } from '../../ports/stores';

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
      if (record.email === email && this.live(record))
        return { ...this.view(record), passwordHash: record.passwordHash };
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

  async setPasswordHash(
    id: string,
    passwordHash: string,
    options: { readonly expected?: string | null } = {},
  ): Promise<boolean> {
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

    if (!record) return;

    record.email = email;
    record.emailVerified = false;
  }

  /** Test helper: give a user no password (a social-only account). */
  async clearPassword(id: string): Promise<void> {
    const record = this.byId.get(id);

    if (record) record.passwordHash = null;
  }
}
