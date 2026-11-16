/**
 * The shared steps every flow runs through. See plugin-context.ts for what
 * each one promises.
 */
import { runInBackground } from './background';
import { DEFAULT_DOOR_LIMITS, type Door } from './config';
import type { CoreDependencies } from './dependencies';
import { firstRefusal, type HookLists, type RevocationReason } from './hooks';
import type { IssuedSession, IssueOptions, PluginContext, SessionAccess } from './plugin-context';
import { narrowSessions } from './session-access';
import { resolveSessionAttributes } from './session-attributes';
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
import type { AuthUser, UserStore } from '../ports/stores';
import type { SessionManager } from '../session/session-manager';
import type { MintInput, MintResult } from '../session/session-types';
import { describeError } from '../shared/describe-error';
import { fail, ok, type AuthFailure, type AuthResult } from '../shared/errors';
import type { RequestMeta } from '../shared/meta';
import { createDeviceToken, verifyDeviceToken } from '../throttle/device-token';
import type { Throttle } from '../throttle/throttle';
import type { OneTimeTokens } from '../tokens/one-time-tokens';

type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;

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

  async mail(event: DistributiveOmit<AuthMailEvent, 'dedupeKey'>): Promise<void> {
    try {
      await this.#deps.mailer.send({
        ...event,
        dedupeKey: generateToken(this.random),
      });
    } catch (error) {
      this.logger.error('Mailer failed', {
        type: event.type,
        userId: event.userId,
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

    const hash = await this.hasher.hash(normalized);

    return ok(hash);
  }

  async issueSession(user: U, options: IssueOptions<A>): Promise<AuthResult<IssuedSession<A>>> {
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

    return ok({ token: minted.token, session: minted.session, cookie, deviceCookie: device });
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
    const token = createDeviceToken(this.#deps.deviceKey, { userId, epoch, issuedAt }, this.random);
    const maxAgeSeconds = Math.floor(this.throttle.deviceMaxAgeMs / 1000);

    return deviceCookie(this.cookie, token, maxAgeSeconds, origin);
  }

  /** The only call that mints a session. Private: every caller goes through `issueSession`. */
  #startSession(input: MintInput<A>): Promise<MintResult<A>> {
    return this.#manager.mint(input);
  }

  /** Runs a task off the response path; failures are logged, never thrown. */
  background(label: string, task: () => Promise<void>): void {
    runInBackground(this.logger, label, task);
  }

  /** The device id when `token` is a valid, unexpired device token for this user at this epoch. */
  verifyDevice(userId: string, epoch: number, token: string | null | undefined): string | null {
    return verifyDeviceToken(this.#deps.deviceKey, token, {
      userId,
      epoch,
      now: this.clock.now(),
      maxAgeMs: this.throttle.deviceMaxAgeMs,
    });
  }

  async revokeAllSessions(userId: string, reason: RevocationReason): Promise<void> {
    const ids = await this.sessions.revokeAll(userId);

    await this.emit({ type: 'sessions.revoked', userId, reason }, undefined);
    await this.notifyRevoked(userId, ids, reason);
  }

  async notifyRevoked(
    userId: string,
    sessionIds: readonly string[],
    reason: RevocationReason,
  ): Promise<void> {
    for (const hook of this.hooks.onSessionsRevoked) {
      try {
        await hook({ userId, sessionIds, reason });
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
