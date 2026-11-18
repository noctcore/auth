/**
 * Sessions: opaque tokens, idle and absolute expiry, and revocation that cannot
 * be raced.
 *
 * - The cookie holds 32 random bytes; the store key is their SHA-256, so a
 *   leaked store holds nothing a client could present.
 * - Absolute expiry is the store TTL (plus `expiresAt` as a backstop). Idle
 *   expiry is per session, decided at mint: a session unused for longer than
 *   its idle timeout is refused and reaped.
 * - `lastActiveAt` is rewritten at most once per `touchInterval`, with an
 *   update-only-if-exists write that keeps the TTL, so a session revoked
 *   between the read and the write is never resurrected.
 * - Revoke-all bumps the user's EPOCH first and only then deletes the sessions
 *   it finds. Every session carries the epoch captured before its credential
 *   was read, and validation refuses a mismatch, so a login that read the old
 *   password hash while a password change was committing cannot produce a live
 *   session even though the cleanup walk never saw it. The mint re-reads the
 *   epoch and rolls back on a mismatch.
 *
 * Guide: Learn, "Sessions and expiry" and "Revocation races and the epoch fence".
 */
import type {
  MintInput,
  MintResult,
  SessionOptions,
  SessionRefusal,
  ValidateResult,
} from './session-types';
import { sha256Hex } from '../crypto/hash';
import { generateToken, isTokenShape, type RandomSource } from '../crypto/random';
import type { Clock } from '../ports/clock';
import type { Logger } from '../ports/logger';
import type { SessionStore, StoredSession } from '../ports/stores';
import { toMilliseconds } from '../shared/duration';
import { AuthConfigError } from '../shared/errors';

export class SessionManager<A> {
  readonly absoluteTtlMs: number;
  readonly rememberMeTtlMs: number;
  readonly touchIntervalMs: number;
  readonly maxPerUser: number | null;

  constructor(
    private readonly store: SessionStore,
    private readonly options: SessionOptions<A>,
    private readonly clock: Clock,
    private readonly random: RandomSource,
    private readonly logger: Logger,
  ) {
    this.absoluteTtlMs = toMilliseconds(options.absoluteTtl ?? '24h');
    this.rememberMeTtlMs = toMilliseconds(options.rememberMeTtl ?? '30d');
    this.touchIntervalMs = toMilliseconds(options.touchInterval ?? '60s');
    this.maxPerUser = options.maxPerUser === undefined ? 10 : options.maxPerUser;

    if (this.maxPerUser !== null && (!Number.isInteger(this.maxPerUser) || this.maxPerUser < 1)) {
      throw new AuthConfigError('session.maxPerUser must be a positive integer or null');
    }

    // An idle timeout chosen per session (a function) can only be checked
    // when a session is minted; a fixed one is checked here, at startup.
    const fixedIdleMs =
      typeof options.idleTimeout === 'function'
        ? null
        : toMilliseconds(options.idleTimeout ?? '30m');

    if (fixedIdleMs !== null && this.touchIntervalMs >= fixedIdleMs) {
      throw new AuthConfigError('session.touchInterval must be shorter than the idle timeout');
    }
  }

  private idleTimeoutMs(rememberMe: boolean, attributes: A): number {
    const configured = this.options.idleTimeout;

    if (typeof configured === 'function')
      return toMilliseconds(configured({ rememberMe, attributes }));
    if (configured !== undefined) return toMilliseconds(configured);

    return toMilliseconds(rememberMe ? '7d' : '30m');
  }

  readEpoch(userId: string): Promise<number> {
    return this.store.getEpoch(userId);
  }

  async mint(input: MintInput<A>): Promise<MintResult<A>> {
    const token = generateToken(this.random);
    const now = this.clock.now();
    const ttlMs = input.rememberMe ? this.rememberMeTtlMs : this.absoluteTtlMs;
    const epoch = input.epoch ?? (await this.store.getEpoch(input.userId));

    const session: StoredSession<A> = {
      id: sha256Hex(token),
      userId: input.userId,
      createdAt: now,
      authenticatedAt: input.authenticatedAt,
      lastActiveAt: now,
      expiresAt: now + ttlMs,
      idleTimeoutMs: this.idleTimeoutMs(input.rememberMe, input.attributes),
      epoch,
      rememberMe: input.rememberMe,
      persistentCookie: input.persistentCookie,
      ip: input.meta.ip,
      userAgent: input.meta.userAgent ?? '',
      attributes: input.attributes,
    };

    await this.store.create(session, ttlMs);

    // Second half of the fence: a revocation that landed after the epoch was
    // captured has already walked (or is walking) the user's sessions and
    // cannot see this one. Re-reading the epoch turns that survivor into a
    // refused login instead of a session that merely dies at its first use.
    const epochNow = await this.store.getEpoch(input.userId);

    if (epochNow !== epoch) {
      await this.store.delete(input.userId, [session.id]);

      this.logger.warn('Session mint lost the epoch fence; a revocation landed mid-login', {
        userId: input.userId,
      });

      return { ok: false, reason: 'epoch_fence' };
    }

    const evicted = await this.evictOverCap(input.userId);

    return { ok: true, token, session, evicted };
  }

  /** Validates a cookie token. `touch: false` for traffic the client makes on its own (polls, socket handshakes). */
  async validate(token: unknown, options: { touch?: boolean } = {}): Promise<ValidateResult<A>> {
    if (!isTokenShape(token)) return { ok: false, reason: 'malformed' };

    const stored = await this.store.get(sha256Hex(token));

    if (!stored) return { ok: false, reason: 'unknown' };

    const now = this.clock.now();
    const refusal = await this.refusalFor(stored, now);

    if (refusal) {
      await this.store.delete(stored.userId, [stored.id]);

      return { ok: false, reason: refusal };
    }

    const session = this.parse(stored);

    if (!session) {
      await this.store.delete(stored.userId, [stored.id]);

      return { ok: false, reason: 'corrupt' };
    }

    if ((options.touch ?? true) && now - session.lastActiveAt >= this.touchIntervalMs) {
      const touched = { ...session, lastActiveAt: now };

      const stillStored = await this.store.touch(touched);

      if (!stillStored) return { ok: false, reason: 'revoked' };

      return { ok: true, session: touched };
    }

    return { ok: true, session };
  }

  private async refusalFor(stored: StoredSession, now: number): Promise<SessionRefusal | null> {
    if (stored.expiresAt <= now) return 'expired';
    if (now >= stored.lastActiveAt + stored.idleTimeoutMs) return 'idle';

    // Strict inequality both ways: a session ahead of the counter (a lost or
    // restored counter) is as untrustworthy as one behind it.
    const epoch = await this.store.getEpoch(stored.userId);

    if (stored.epoch !== epoch) return 'epoch';

    return null;
  }

  private parse(stored: StoredSession): StoredSession<A> | null {
    if (!this.options.attributes) return stored as StoredSession<A>;

    try {
      return { ...stored, attributes: this.options.attributes.parse(stored.attributes) };
    } catch {
      // Attribute content stays unlogged: it can carry identity claims.
      this.logger.warn('Session attributes failed validation; treating the session as invalid', {
        userId: stored.userId,
      });

      return null;
    }
  }

  /**
   * The session stored under `id` if it is live: unexpired, not idle, on its
   * user's current epoch, with valid attributes. Null otherwise. Never touches
   * or reaps; a read for a decision, not a validation.
   */
  async findActive(id: string): Promise<StoredSession<A> | null> {
    const stored = await this.store.get(id);

    if (!stored || (await this.refusalFor(stored, this.clock.now()))) return null;

    return this.parse(stored);
  }

  /** The user's live sessions: unexpired, not idle, on the current epoch, valid attributes. Reaps the rest. */
  async listActive(userId: string): Promise<StoredSession<A>[]> {
    const sessions = await this.store.listByUser(userId);
    const epoch = await this.store.getEpoch(userId);
    const now = this.clock.now();
    const active: StoredSession<A>[] = [];
    const stale: string[] = [];

    for (const stored of sessions) {
      const live =
        stored.expiresAt > now &&
        now < stored.lastActiveAt + stored.idleTimeoutMs &&
        stored.epoch === epoch;

      const parsed = live ? this.parse(stored) : null;

      if (parsed) active.push(parsed);
      else stale.push(stored.id);
    }

    if (stale.length > 0) await this.store.delete(userId, stale);

    return active;
  }

  /**
   * Runs AFTER the new session is written, so concurrent logins converge to
   * the cap instead of all passing a pre-write check. Oldest first; the new
   * session has the newest createdAt.
   *
   * Returns the ids this call removed, as the store reports them: two logins
   * racing at the cap may pick the same oldest session, and only the one whose
   * delete removed it reports it, so each eviction reaches the hooks once.
   */
  private async evictOverCap(userId: string): Promise<string[]> {
    if (this.maxPerUser === null) return [];

    const active = await this.listActive(userId);

    if (active.length <= this.maxPerUser) return [];

    active.sort((a, b) => a.createdAt - b.createdAt);
    const chosen = active.slice(0, active.length - this.maxPerUser).map((s) => s.id);

    return this.deleteAndReport(userId, chosen);
  }

  /**
   * Deletes the sessions and returns the ids this call removed, so that of an
   * eviction racing a logout or a revocation, only the call that removed a
   * session reports it, under one reason. A store that does not answer with
   * an array (an older store returning nothing, or a count) is taken to have
   * removed every id it was given.
   */
  private async deleteAndReport(userId: string, ids: readonly string[]): Promise<string[]> {
    if (ids.length === 0) return [];

    const removed: unknown = await this.store.delete(userId, ids);

    if (!Array.isArray(removed)) return [...ids];

    const confirmed = new Set<unknown>(removed);

    return ids.filter((id) => confirmed.has(id));
  }

  /** Deletes the named sessions if they belong to the user. Returns the ids this call removed. */
  async revoke(userId: string, ids: readonly string[]): Promise<string[]> {
    const sessions = await this.store.listByUser(userId);
    const owned = new Set(sessions.map((s) => s.id));

    return this.deleteAndReport(
      userId,
      ids.filter((id) => owned.has(id)),
    );
  }

  /**
   * Deletes the session a token names (single-device logout; no epoch bump).
   * Returns it only if this call removed it: a session another call ended
   * first (an eviction, a revocation) was already reported there.
   */
  async revokeToken(token: unknown): Promise<StoredSession | null> {
    if (!isTokenShape(token)) return null;

    const stored = await this.store.get(sha256Hex(token));

    if (!stored) return null;

    const removed = await this.deleteAndReport(stored.userId, [stored.id]);

    return removed.length > 0 ? stored : null;
  }

  /**
   * Revokes every session of the user. The epoch bump IS the revocation; the
   * walk only reclaims storage. Call it only after the state change that
   * motivates it (a new password hash) has been written.
   */
  async revokeAll(userId: string): Promise<string[]> {
    const epoch = await this.store.bumpEpoch(userId);

    // A session stamped with the new epoch is a login that started after the
    // revocation; it is legitimate and stays.
    const sessions = await this.store.listByUser(userId);
    const ids = sessions.filter((s) => s.epoch < epoch).map((s) => s.id);

    return this.deleteAndReport(userId, ids);
  }
}
