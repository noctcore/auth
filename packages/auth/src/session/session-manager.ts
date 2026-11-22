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
import { assertIdleOutlastsTouch } from './idle-rule';
import { lookUpSession } from './legacy-sessions';
import { sha256Hex } from '../crypto/hash';
import { generateToken, isTokenShape, type RandomSource } from '../crypto/random';
import type { Clock } from '../ports/clock';
import type { Logger } from '../ports/logger';
import type { SessionStore, StoredSession } from '../ports/stores';
import { configMilliseconds } from '../shared/config-checks';
import { toMilliseconds } from '../shared/duration';
import { AuthConfigError } from '../shared/errors';

export class SessionManager<A> {
  readonly absoluteTtlMs: number;
  readonly rememberMeTtlMs: number;
  readonly touchIntervalMs: number;
  readonly maxPerUser: number | null;
  /** How long the store keeps a user's epoch after its last write; undefined when it never lapses. */
  readonly epochTtlMs: number | undefined;

  constructor(
    private readonly store: SessionStore,
    private readonly options: SessionOptions<A>,
    private readonly clock: Clock,
    private readonly random: RandomSource,
    private readonly logger: Logger,
  ) {
    this.absoluteTtlMs = configMilliseconds('session.absoluteTtl', options.absoluteTtl, '24h');

    this.rememberMeTtlMs = configMilliseconds(
      'session.rememberMeTtl',
      options.rememberMeTtl,
      '30d',
    );

    this.touchIntervalMs = configMilliseconds(
      'session.touchInterval',
      options.touchInterval,
      '60s',
    );

    this.maxPerUser = options.maxPerUser === undefined ? 10 : options.maxPerUser;
    this.epochTtlMs = store.epochTtlMs;

    if (this.maxPerUser !== null && (!Number.isInteger(this.maxPerUser) || this.maxPerUser < 1)) {
      throw new AuthConfigError('session.maxPerUser must be a positive integer or null');
    }

    // A fixed idle timeout is checked here, at startup; one chosen per session
    // (a function) is checked against the same rule each time a session is
    // minted (see `idleTimeoutMs`).
    if (typeof options.idleTimeout !== 'function') {
      assertIdleOutlastsTouch(
        configMilliseconds('session.idleTimeout', options.idleTimeout, '30m'),
        this.touchIntervalMs,
      );
    }

    // Read on every session read: a schema without `parse` would throw there.
    if (
      options.attributes !== undefined &&
      options.attributes !== null &&
      typeof options.attributes.parse !== 'function'
    )
      throw new AuthConfigError('session.attributes must be a schema with a parse function');
  }

  private idleTimeoutMs(rememberMe: boolean, attributes: A): number {
    const configured = this.options.idleTimeout;

    if (typeof configured === 'function') {
      const idleMs = toMilliseconds(configured({ rememberMe, attributes }));

      // Thrown before anything is read or written, like a bad fixed value at
      // startup: the login fails loudly instead of issuing a session that
      // dies while it is in use.
      assertIdleOutlastsTouch(idleMs, this.touchIntervalMs);

      return idleMs;
    }

    // Null is left out, as at startup: the default, not a parse error on every sign-in.
    if (configured !== undefined && configured !== null) return toMilliseconds(configured);

    return toMilliseconds(rememberMe ? '7d' : '30m');
  }

  readEpoch(userId: string): Promise<number> {
    return this.store.getEpoch(userId);
  }

  async mint(input: MintInput<A>): Promise<MintResult<A>> {
    const token = generateToken(this.random);
    const idleTimeoutMs = this.idleTimeoutMs(input.rememberMe, input.attributes);

    // The sessions written before this mint began, read before the clock so
    // that a session in it was also stamped before this one on a shared clock.
    const before = new Set(
      this.maxPerUser === null ? [] : (await this.store.listByUser(input.userId)).map((s) => s.id),
    );

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
      idleTimeoutMs,
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

    const evicted = await this.evictOverCap(input.userId, session, before);

    return { ok: true, token, session, evicted };
  }

  /** Validates a cookie token. `touch: false` for traffic the client makes on its own (polls, socket handshakes). */
  async validate(token: unknown, options: { touch?: boolean } = {}): Promise<ValidateResult<A>> {
    if (!isTokenShape(token)) return { ok: false, reason: 'malformed' };

    const { session: stored, adopting } = await lookUpSession(
      this.store,
      sha256Hex(token),
      this.touchIntervalMs,
    );

    if (!stored) return { ok: false, reason: adopting ? 'adopting' : 'unknown' };

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
   * the cap instead of all passing a pre-write check. Oldest first, by
   * `createdAt` and then by id (unique, so never equal), so racing logins
   * agree on the order whatever order the store lists in.
   *
   * The session this mint wrote (`self`) is never a candidate. Another session
   * is one when it was stored before this mint began (`before`), whatever its
   * timestamp, so a tie in `createdAt` or an instance whose clock is behind
   * still evicts the older session. A session written while this mint ran is
   * one only when it sorts before `self`: of two logins racing at a cap of
   * one, only the one that sorts first is evicted, by the other.
   *
   * What is left: a racing session that sorts after `self` is not evicted
   * here, even if its own mint has already finished and will not evict
   * `self` (its eviction ran before `self` was written, and its timestamp is
   * newer). The user then holds one session over the cap until the next
   * mint. And when one login was written before the other began but sorts
   * after it (a clock behind, or a tie broken by id), and both evict after
   * both are written, each evicts the other.
   *
   * Returns the ids this call removed, as the store reports them: two logins
   * racing at the cap may pick the same oldest session, and only the one whose
   * delete removed it reports it, so each eviction reaches the hooks once.
   */
  private async evictOverCap(
    userId: string,
    self: StoredSession<A>,
    before: ReadonlySet<string>,
  ): Promise<string[]> {
    if (this.maxPerUser === null) return [];

    const active = await this.listActive(userId);
    const excess = active.length - this.maxPerUser;

    if (excess <= 0) return [];

    const chosen = active
      .filter((s) => s.id !== self.id && (before.has(s.id) || olderFirst(s, self) < 0))
      .sort(olderFirst)
      .slice(0, excess)
      .map((s) => s.id);

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

/** The eviction order: oldest `createdAt` first, then by id (unique, so never equal). */
function olderFirst(a: StoredSession, b: StoredSession): number {
  return a.createdAt - b.createdAt || (a.id < b.id ? -1 : 1);
}
