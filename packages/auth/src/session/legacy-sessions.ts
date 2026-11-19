/**
 * Adopting the sessions an app stored before it switched to the package's
 * session store, so the switch does not sign every user out.
 *
 * The danger is a second, unguarded way in: a legacy record the package's
 * revocations never see. So a legacy record is adopted at most once and only
 * as a package session that every guard then applies to:
 *
 * - `take` removes the legacy record as it reads it, before the package
 *   session is written. A sign-out or revocation of the adopted session cannot
 *   be undone by the legacy record being adopted again, and of two requests
 *   racing on one cookie only one adopts it. The other looks for the session
 *   the first is writing, once more after a short wait, and is refused if it
 *   is still missing, with the reason `adopting`: the adapters keep the
 *   cookie of such a refusal (`clearsSessionCookie`), since the next request
 *   may find the session the first one wrote.
 * - The adopted session is stamped with epoch 0, the epoch of a user whose
 *   sessions were never revoked. A sign-out everywhere or a password change
 *   after the switch bumps the epoch, so legacy sessions the user never
 *   presented since are refused when they are.
 * - Its absolute expiry is never later than its legacy expiry, nor than
 *   `maxTtl` after it was created, so no legacy session outlives a store's
 *   epoch TTL and the wrapper has nothing left to adopt `maxTtl` after the
 *   switch.
 * - A record that is expired, created in the future or not well formed is
 *   dropped, never adopted.
 *
 * Guide: Build, "Writing a store adapter", section "Switching from your own
 * sessions".
 */
import { systemClock, type Clock } from '../ports/clock';
import type { Logger } from '../ports/logger';
import type { SessionStore, StoredSession } from '../ports/stores';
import { toMilliseconds, type Duration } from '../shared/duration';
import { AuthConfigError } from '../shared/errors';

/** A legacy session converted by the app. The id and the epoch are the wrapper's to set. */
export interface LegacySession {
  readonly userId: string;
  readonly createdAt: number;
  /**
   * When the user last proved a credential: it grants fresh-auth standing
   * (`requireFreshAuth`). Report `createdAt` unless the legacy store recorded
   * a later sign-in or re-authentication.
   */
  readonly authenticatedAt: number;
  readonly lastActiveAt: number;
  readonly expiresAt: number;
  readonly idleTimeoutMs: number;
  readonly rememberMe: boolean;
  /** Defaults to `rememberMe`. */
  readonly persistentCookie?: boolean;
  readonly ip?: string;
  readonly userAgent?: string;
  /** Checked by `session.attributes` like any session's. Defaults to `{}`. */
  readonly attributes?: unknown;
}

export interface LegacySessionOptions {
  /**
   * Removes and returns the legacy session stored under `id` (the SHA-256 hex
   * of the cookie token, the package's store key), converted to a
   * `LegacySession`; null when there is none. Must be atomic: of concurrent
   * callers for one id, at most one gets the session.
   */
  take(id: string): Promise<LegacySession | null>;
  /**
   * The longest a legacy session may live, counted from its `createdAt`. Set
   * it to `session.rememberMeTtl`. The store's `maxSessionTtlMs`, when
   * shorter, wins.
   */
  readonly maxTtl: Duration;
  /** Defaults to the system clock. */
  readonly clock?: Clock;
  readonly logger?: Logger;
}

/**
 * How long a request that lost the race for a legacy record waits before its
 * last look for the session the winner is writing. Every cookie neither store
 * knows pays it once while the wrapper is in place.
 */
const RACE_WAIT_MS = 50;

/**
 * What the session manager reads through the wrapper: the session, and
 * whether a refusal may be a lost race for a record another request is still
 * adopting. Internal: the key is not exported from the package.
 */
export const LEGACY_LOOKUP = Symbol('noctcore.legacyLookup');

interface Lookup {
  readonly session: StoredSession | null;
  /**
   * True when neither store had the session and the legacy store had no
   * record either: a request racing this one may have taken it and still be
   * writing it. Not knowable across processes, so every such token reports it.
   */
  readonly adopting: boolean;
}

type AdoptingStore = SessionStore & { readonly [LEGACY_LOOKUP]?: (id: string) => Promise<Lookup> };

/** The session under `id`, and whether a refusal may be a pending adoption; plain stores never report one. */
export async function lookUpSession(store: SessionStore, id: string): Promise<Lookup> {
  const lookup = (store as AdoptingStore)[LEGACY_LOOKUP];

  return lookup ? lookup(id) : { session: await store.get(id), adopting: false };
}

const isTime = (value: unknown): value is number =>
  typeof value === 'number' && Number.isFinite(value) && value >= 0;

/**
 * Wraps the package's session store: a session it does not hold is looked up
 * once in the legacy store and, if live, written to it in the package's format
 * and removed from the legacy store. Everything else passes through.
 */
export function adoptLegacySessions(
  store: SessionStore,
  options: LegacySessionOptions,
): SessionStore {
  const configuredMs = toMilliseconds(options.maxTtl);

  if (configuredMs <= 0) {
    throw new AuthConfigError('adoptLegacySessions: maxTtl must be a positive duration');
  }

  const maxTtlMs = Math.min(configuredMs, store.maxSessionTtlMs ?? Infinity);
  const clock = options.clock ?? systemClock;

  function convert(id: string, legacy: LegacySession, now: number): StoredSession | null {
    const times = [legacy.createdAt, legacy.authenticatedAt, legacy.lastActiveAt, legacy.expiresAt];

    if (typeof legacy.userId !== 'string' || legacy.userId === '') return null;
    if (!times.every(isTime) || !isTime(legacy.idleTimeoutMs) || legacy.idleTimeoutMs === 0)
      return null;
    if (legacy.createdAt > now || typeof legacy.rememberMe !== 'boolean') return null;

    return {
      id,
      userId: legacy.userId,
      createdAt: legacy.createdAt,
      authenticatedAt: Math.min(legacy.authenticatedAt, now),
      lastActiveAt: Math.min(legacy.lastActiveAt, now),
      expiresAt: Math.min(legacy.expiresAt, legacy.createdAt + maxTtlMs),
      idleTimeoutMs: legacy.idleTimeoutMs,
      epoch: 0,
      rememberMe: legacy.rememberMe,
      persistentCookie: legacy.persistentCookie ?? legacy.rememberMe,
      ip: legacy.ip ?? '',
      userAgent: legacy.userAgent ?? '',
      attributes: legacy.attributes ?? {},
    };
  }

  async function adopt(id: string): Promise<Lookup> {
    const legacy = await options.take(id);

    // Nothing to adopt: either no legacy session, or a request racing this one
    // on the same cookie took the record first. That request may still be
    // inside `store.create` on a database round trip, so look once more after
    // a short wait, then fail closed, reporting the refusal as a possible
    // pending adoption so the cookie is kept for the next request.
    if (!legacy) {
      const written = await store.get(id);

      if (written) return { session: written, adopting: false };

      await new Promise<void>((resolve) => setTimeout(resolve, RACE_WAIT_MS));

      const late = await store.get(id);

      return { session: late, adopting: late === null };
    }

    const now = clock.now();
    const session = convert(id, legacy, now);

    if (!session) {
      options.logger?.warn('Dropped a legacy session that is not well formed', {
        userId: typeof legacy.userId === 'string' ? legacy.userId : undefined,
      });

      return { session: null, adopting: false };
    }

    if (session.expiresAt <= now) return { session: null, adopting: false };

    await store.create(session, session.expiresAt - now);

    return { session, adopting: false };
  }

  async function lookup(id: string): Promise<Lookup> {
    const stored = await store.get(id);

    return stored ? { session: stored, adopting: false } : adopt(id);
  }

  const wrapped: AdoptingStore = {
    [LEGACY_LOOKUP]: lookup,
    create: (session, ttlMs) => store.create(session, ttlMs),
    get: async (id) => (await lookup(id)).session,
    touch: (session) => store.touch(session),
    delete: (userId, ids) => store.delete(userId, ids),
    listByUser: (userId) => store.listByUser(userId),
    getEpoch: (userId) => store.getEpoch(userId),
    bumpEpoch: (userId) => store.bumpEpoch(userId),
  };

  return store.maxSessionTtlMs === undefined
    ? wrapped
    : { ...wrapped, maxSessionTtlMs: store.maxSessionTtlMs };
}
