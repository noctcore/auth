/**
 * The shared steps every flow runs through. See plugin-context.ts for what
 * each one promises.
 */
import { DEFAULT_DOOR_LIMITS, type Door } from './config';
import type { CoreDependencies } from './dependencies';
import { firstRefusal, type HookLists, type IssueVia, type RevocationReason } from './hooks';
import type { IssuedSession, IssueOptions, PluginContext, SessionAccess } from './plugin-context';
import { narrowSessions } from './session-access';
import { resolveSessionAttributes } from './session-attributes';
import { hmacSha256Base64url, hmacSha256Hex, secretsEqual } from '../crypto/hash';
import { deriveKey } from '../crypto/keys';
import { generateToken, type RandomSource } from '../crypto/random';
import {
  createSessionCookie,
  deviceCookie,
  type CookieSpec,
  type SessionCookieConfig,
} from '../http/cookie';
import type { PasswordHasher } from '../password/hasher';
import { checkPasswordPolicy, normalizePassword, type PasswordPolicy } from '../password/policy';
import { verifyPasswordHash } from '../password/verify';
import type { AuthEvent } from '../ports/audit';
import type { CaptchaDoor } from '../ports/captcha';
import type { Clock } from '../ports/clock';
import type { Logger, Metrics } from '../ports/logger';
import type { AuthMailEvent } from '../ports/mail';
import type { AuthUser, StoredSession, UserStore, WithPasswordHash } from '../ports/stores';
import type { SessionManager } from '../session/session-manager';
import type { MintInput, MintResult } from '../session/session-types';
import { describeError } from '../shared/describe-error';
import type { NormalizedEmail } from '../shared/email';
import { fail, ok, type AuthFailure, type AuthResult } from '../shared/errors';
import type { RequestMeta } from '../shared/meta';
import { createDeviceToken, verifyDeviceToken } from '../throttle/device-token';
import type { Throttle } from '../throttle/throttle';
import type { OneTimeTokens } from '../tokens/one-time-tokens';

type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;

/** Vias that re-issue a session the user already holds: they must pass it as `inherit`. */
const REISSUE_VIAS: ReadonlySet<IssueVia> = new Set([
  'password-change',
  'reauthenticate',
  'revoke-others',
  'email-verified',
  'email-changed',
]);

export class AuthCore<U extends AuthUser, A> implements PluginContext<U, A> {
  readonly users: UserStore<U>;
  /** Everything about sessions except minting, which only `issueSession` may do. */
  readonly sessions: SessionAccess<A>;
  readonly tokens: OneTimeTokens;
  readonly throttle: Throttle;
  readonly hasher: PasswordHasher;
  readonly policy: PasswordPolicy;
  readonly hooks: HookLists<U, A>;
  readonly clock: Clock;
  readonly random: RandomSource;
  readonly logger: Logger;
  readonly metrics: Metrics;
  readonly cookie: SessionCookieConfig;

  // Native private fields: unreachable from plugins and from `auth.context` at runtime.
  readonly #deps: CoreDependencies<U, A>;
  readonly #manager: SessionManager<A>;
  /** Sessions `confirmLiveSession` read live, each good for one re-issue. */
  readonly #confirmed = new WeakSet<StoredSession<A>>();

  constructor(deps: CoreDependencies<U, A>) {
    this.#deps = deps;
    this.#manager = deps.sessions;
    this.users = deps.users;
    this.sessions = Object.freeze(narrowSessions(deps.sessions));
    this.tokens = deps.tokens;
    this.throttle = deps.throttle;
    this.hasher = deps.hasher;
    this.policy = deps.policy;
    this.hooks = deps.hooks;
    this.clock = deps.clock;
    this.random = deps.random;
    this.logger = deps.logger;
    this.metrics = deps.metrics;
    this.cookie = deps.cookie;
  }

  sessionHandle(sessionId: string): string {
    return hmacSha256Base64url(this.#deps.handleKeys[0], sessionId);
  }

  /**
   * Whether `handle` names the session stored under `sessionId`, under the
   * current handle key or a previous secret's. Every key is tried.
   */
  matchesSessionHandle(sessionId: string, handle: string): boolean {
    const matches = this.#deps.handleKeys.map((key) =>
      secretsEqual(hmacSha256Base64url(key, sessionId), handle),
    );

    return matches.includes(true);
  }

  keyedHash(purpose: string, message: string): string {
    return hmacSha256Hex(deriveKey(this.#deps.pluginKeys[0], purpose), message);
  }

  keyedHashes(purpose: string, message: string): readonly [string, ...string[]] {
    const [current, ...previous] = this.#deps.pluginKeys;

    return [
      hmacSha256Hex(deriveKey(current, purpose), message),
      ...previous.map((key) => hmacSha256Hex(deriveKey(key, purpose), message)),
    ];
  }

  normalizeEmail(input: unknown): NormalizedEmail | null {
    const verdict = this.#deps.emails(input);

    return verdict.ok ? verdict.email : null;
  }

  parseEmail(input: unknown): AuthResult<NormalizedEmail> {
    const verdict = this.#deps.emails(input);

    return verdict.ok ? ok(verdict.email) : fail(verdict.reason, verdict.reason);
  }

  isAddressHeld(email: NormalizedEmail): Promise<boolean> {
    return this.#deps.addressHeld(email);
  }

  async findCredentialByEmail(email: NormalizedEmail): Promise<WithPasswordHash<U> | null> {
    const found = await this.users.findCredentialByEmail(email);

    if (!found) return null;

    if (found.email !== email) {
      // A row stored in a spelling the normaliser would not produce (written
      // outside the flows, or read through an insensitive collation) is not
      // this address: its owner cannot sign in by it until the row is fixed.
      // Logged with the user id only, never an address.
      this.logger.warn(
        'User store returned a row whose stored email is not the normalised address; treating it as not found',
        { userId: found.id },
      );

      return null;
    }

    return found;
  }

  requireFreshAuth(session: StoredSession<A>): AuthResult<void> {
    return this.clock.now() - session.authenticatedAt <= this.#deps.freshAuthAgeMs
      ? ok()
      : fail('fresh_auth_required', 'stale_authentication');
  }

  async requireFreshLiveSession(session: StoredSession<A>): Promise<AuthResult<StoredSession<A>>> {
    const live = await this.#manager.findActive(session.id);

    if (!live || live.userId !== session.userId)
      return fail('session_expired', 'session_not_active');

    const fresh = this.requireFreshAuth(live);

    return fresh.ok ? ok(live) : fresh;
  }

  async emit(event: AuthEvent, meta: RequestMeta | undefined): Promise<void> {
    const tags: Record<string, string> = event.reason
      ? { type: event.type, reason: event.reason }
      : { type: event.type };

    this.metrics.count('auth_event', tags);

    if (!this.#deps.audit) return;

    try {
      await this.#deps.audit.emit(event, meta);
    } catch (error) {
      this.logger.error('Audit sink failed', { type: event.type, error: describeError(error) });
    }
  }

  mail(event: DistributiveOmit<AuthMailEvent, 'dedupeKey'>): void {
    // Everything inside the task, the dedupe key included, so nothing here can
    // throw into the flow. `send` itself is still called before `mail`
    // returns: its synchronous part runs on the response path.
    this.background(
      `mail ${event.type}`,
      () => this.deliver(event),
      'userId' in event ? { userId: event.userId } : undefined,
    );
  }

  /**
   * Sends a mail and waits for the send, for work that already runs off the
   * response path (a background task, a queue job): the send then belongs to
   * that task, its slot under `maxPending`, its timeout and `flush`, instead
   * of starting a task of its own. Logs a failure, never throws.
   */
  async deliver(event: DistributiveOmit<AuthMailEvent, 'dedupeKey'>): Promise<void> {
    try {
      await this.#deps.mailer.send({ ...event, dedupeKey: generateToken(this.random) });
    } catch (error) {
      this.logger.error('Mailer failed', {
        type: event.type,
        ...('userId' in event ? { userId: event.userId } : {}),
        error: describeError(error),
      });
    }
  }

  async rateLimit(
    door: Door,
    key: string,
    meta: RequestMeta | undefined,
  ): Promise<AuthFailure | null> {
    const rule = this.#deps.doors[door] ?? DEFAULT_DOOR_LIMITS[door];
    const hit = await this.throttle.hit(`${door}:${key}`, rule);

    if (hit.allowed) return null;
    if (hit.firstRefusal) await this.emit({ type: 'rate_limit.exceeded', reason: door }, meta);

    return fail('rate_limited', `rate_limited:${door}`, {
      retryAfterSeconds: hit.retryAfterSeconds,
    });
  }

  async checkCaptcha(
    door: CaptchaDoor,
    token: string | undefined,
    meta: RequestMeta,
  ): Promise<AuthFailure | null> {
    if (!this.#deps.captcha) return null;

    const verdict = await this.#deps.captcha.verify(token, { ip: meta.ip, door });

    this.metrics.count('auth_captcha', { door, verdict });

    if (verdict === 'pass') return null;

    return verdict === 'unavailable'
      ? fail('captcha_unavailable', 'captcha_unavailable')
      : fail('captcha_failed', 'captcha_rejected');
  }

  async verifyPassword(
    passwordHash: string | null | undefined,
    password: string,
  ): Promise<boolean> {
    return verifyPasswordHash(this.hasher, this.policy, passwordHash, password);
  }

  async hashNewPassword(
    password: string,
    meta: RequestMeta | undefined,
  ): Promise<AuthResult<string>> {
    const checked = await this.checkNewPassword(password, meta);

    return checked.ok ? ok(await this.hasher.hash(checked.value)) : checked;
  }

  /**
   * The policy and breach checks of `hashNewPassword`, without the hash:
   * returns the normalized password to pass to `hashCheckedPassword`. For a
   * flow whose hooks run between the two, so a refused password spends
   * nothing a hook asked for and a hook's refusal costs no hash.
   */
  async checkNewPassword(
    password: string,
    meta: RequestMeta | undefined,
  ): Promise<AuthResult<string>> {
    const verdict = checkPasswordPolicy(password, this.policy);

    if (verdict === 'too_short') return fail('weak_password', 'password_too_short');
    if (verdict === 'too_long') return fail('password_too_long', 'password_too_long');

    const normalized = normalizePassword(password);

    if (this.#deps.breachCheck) {
      const breach = await this.#deps.breachCheck(normalized);

      this.metrics.count('auth_breach_check', { verdict: breach });

      if (breach === 'breached') return fail('breached_password', 'password_breached');

      if (breach === 'unavailable') {
        this.logger.warn('Breached-password check unavailable; accepting the password unchecked');

        await this.emit(
          { type: 'password.breach_check_unavailable', data: { accepted: true } },
          meta,
        );
      }
    }

    return ok(normalized);
  }

  /** Hashes a password `checkNewPassword` accepted (and normalized). */
  async hashCheckedPassword(normalized: string): Promise<string> {
    return this.hasher.hash(normalized);
  }

  /**
   * Re-reads `session` from the store and returns the stored copy if it is
   * live (unexpired, not idle, current epoch) and still the same user's; null
   * otherwise. A re-issue flow calls this BEFORE it revokes anything and
   * passes the returned object as `inherit`: only such an object, once, opens
   * the re-issue vias of `issueSession`.
   */
  async confirmLiveSession(session: StoredSession<A>): Promise<StoredSession<A> | null> {
    const live = await this.#manager.findActive(session.id);

    if (!live || live.userId !== session.userId) return null;

    this.#confirmed.add(live);

    return live;
  }

  /** Whether `inherit` came from `confirmLiveSession` for this user; spends it either way. */
  #takeConfirmed(inherit: StoredSession<A> | undefined, userId: string): boolean {
    if (!inherit || !this.#confirmed.delete(inherit)) return false;

    return inherit.userId === userId;
  }

  async issueSession(user: U, options: IssueOptions<A>): Promise<AuthResult<IssuedSession<A>>> {
    // A re-issue names the session it replaces, and that session was read live
    // from the store, for this user, by `confirmLiveSession` before the flow
    // revoked anything: hooks (a second factor's enforcement, say) let
    // re-issues through on the strength of that, so a call that only claims the
    // label, or hands over a revoked, expired or hand-built session, is refused.
    if (REISSUE_VIAS.has(options.via) && !this.#takeConfirmed(options.inherit, user.id)) {
      await this.#loginFailure(user, `reissue_without_session:${options.via}`, options);

      return fail('session_expired', `reissue_without_session:${options.via}`);
    }

    const resolved = await resolveSessionAttributes(
      { hooks: this.hooks, schema: this.#deps.attributeSchema, logger: this.logger },
      user,
      options,
    );

    if (!resolved.ok) return resolved;

    const attributes = resolved.value;

    const refusal = await firstRefusal(this.hooks.beforeSessionCreate, {
      user,
      via: options.via,
      attributes,
      meta: options.meta,
    });

    if (refusal) {
      await this.#loginFailure(user, refusal.reason, options);

      return fail(refusal.code, refusal.reason);
    }

    const rememberMe = options.rememberMe ?? options.inherit?.rememberMe ?? false;

    const persistentCookie =
      options.persistentCookie ?? options.inherit?.persistentCookie ?? rememberMe;

    const minted = await this.#startSession({
      userId: user.id,
      attributes,
      rememberMe,
      persistentCookie,
      authenticatedAt: options.authenticatedAt ?? this.clock.now(),
      meta: options.meta,
      ...(options.epoch === undefined ? {} : { epoch: options.epoch }),
    });

    if (!minted.ok) {
      await this.#loginFailure(user, minted.reason, options);

      return fail('session_expired', minted.reason);
    }

    // A grant: its audit row is written before the session is handed out.
    await this.emit(
      { type: 'session.created', userId: user.id, data: { via: options.via, rememberMe } },
      options.meta,
    );

    // `emit` logs a failing audit sink and `notifyRevoked` logs a failing hook,
    // so neither stops the evictions reaching the hooks or fails the sign-in.
    // The hooks are awaited here, on the sign-in path.
    if (minted.evicted.length > 0) await this.notifyRevoked(user.id, minted.evicted, 'evicted');

    const cookie = createSessionCookie(this.cookie, minted.token, {
      expiresAt: minted.session.expiresAt,
      persistent: persistentCookie,
      now: this.clock.now(),
      origin: options.meta.origin,
    });

    // Only here, after every factor: the device token for the lockout bypass,
    // bound to the user and the epoch the session was stamped with.
    const device = this.#deviceCookie(user.id, minted.session.epoch, options.meta.origin);

    return ok({
      token: minted.token,
      session: minted.session,
      cookie,
      deviceCookie: device,
      evicted: minted.evicted,
      evictedHandles: minted.evicted.map((id) => this.sessionHandle(id)),
    });
  }

  /** The audit row for a sign-in that got this far and was still refused. */
  async #loginFailure(user: U, reason: string, options: IssueOptions<A>): Promise<void> {
    await this.emit(
      { type: 'login.failure', userId: user.id, reason, data: { via: options.via } },
      options.meta,
    );
  }

  /** A trusted-device cookie for a session just issued at `epoch`. */
  #deviceCookie(userId: string, epoch: number, origin: string | undefined): CookieSpec {
    const issuedAt = this.clock.now();

    const token = createDeviceToken(
      this.#deps.deviceKeys[0],
      { userId, epoch, issuedAt },
      this.random,
    );

    const maxAgeSeconds = Math.floor(this.throttle.deviceMaxAgeMs / 1000);

    return deviceCookie(this.cookie, token, maxAgeSeconds, origin);
  }

  /** The only call that mints a session. Private: every caller goes through `issueSession`. */
  #startSession(input: MintInput<A>): Promise<MintResult<A>> {
    return this.#manager.mint(input);
  }

  /**
   * Runs a task off the response path; failures are logged, never thrown.
   * `details` (ids, never user input) go into the log lines about the task.
   * Mail inside the task goes through `deliver`, not `mail`.
   */
  background(
    label: string,
    task: () => Promise<void>,
    details?: Readonly<Record<string, string>>,
    options?: { readonly uncapped?: boolean },
  ): void {
    this.#deps.background.run(label, task, details, options);
  }

  /**
   * Writes an audit event off the response path, as a task `maxPending` never
   * drops: under a cap, mail can be dropped, the audit trail cannot.
   */
  auditInBackground(event: AuthEvent, meta: RequestMeta | undefined): void {
    this.background(
      `audit ${event.type}`,
      () => this.emit(event, meta),
      event.userId === undefined ? undefined : { userId: event.userId },
      { uncapped: true },
    );
  }

  /**
   * The device id when `token` is a valid, unexpired device token for this
   * user at this epoch, under the current device key or a previous secret's.
   * Every key is tried; the next sign-in writes a new cookie under the current one.
   */
  verifyDevice(userId: string, epoch: number, token: string | null | undefined): string | null {
    const check = { userId, epoch, now: this.clock.now(), maxAgeMs: this.throttle.deviceMaxAgeMs };
    const ids = this.#deps.deviceKeys.map((key) => verifyDeviceToken(key, token, check));

    return ids.find((id) => id !== null) ?? null;
  }

  async revokeAllSessions(
    userId: string,
    reason: RevocationReason,
    options: { scope?: string } = {},
  ): Promise<void> {
    const ids = await this.sessions.revokeAll(userId);

    await this.emit({ type: 'sessions.revoked', userId, reason }, undefined);
    await this.notifyRevoked(userId, ids, reason, options);
  }

  async notifyRevoked(
    userId: string,
    sessionIds: readonly string[],
    reason: RevocationReason,
    options: { scope?: string } = {},
  ): Promise<void> {
    const sessionHandles = sessionIds.map((id) => this.sessionHandle(id));

    const context =
      options.scope === undefined
        ? { userId, sessionIds, sessionHandles, reason }
        : { userId, sessionIds, sessionHandles, reason, scope: options.scope };

    for (const hook of this.hooks.onSessionsRevoked) {
      try {
        await hook(context);
      } catch (error) {
        this.logger.error('onSessionsRevoked hook failed', {
          userId,
          reason,
          error: describeError(error),
        });
      }
    }
  }
}
