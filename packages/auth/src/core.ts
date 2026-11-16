/**
 * The shared steps every flow runs through. See plugin-context.ts for what
 * each one promises.
 */
import type { AuditSink, AuthEvent } from './audit';
import type { CaptchaDoor, CaptchaVerifier } from './captcha';
import type { Clock } from './clock';
import { createSessionCookie, type SessionCookieConfig } from './cookie';
import { DEFAULT_DOOR_LIMITS, type Door } from './config';
import { fail, ok, type AuthFailure, type AuthResult } from './errors';
import { firstRefusal, type HookLists, type RevocationReason } from './hooks';
import type { Logger, Metrics } from './logger';
import type { AuthMailEvent, Mailer } from './mail';
import type { RequestMeta } from './meta';
import type { BreachChecker } from './password/breach';
import { dummyHashFor, type PasswordHasher } from './password/hasher';
import { checkPasswordPolicy, normalizePassword, type PasswordPolicy } from './password/policy';
import type { IssuedSession, IssueOptions, PluginContext } from './plugin-context';
import { generateToken, type RandomSource } from './random';
import type { AttributeSchema, SessionManager } from './session';
import type { AuthUser, UserStore } from './stores';
import type { RateLimitRule, Throttle } from './throttle';
import type { OneTimeTokens } from './tokens';

export interface CoreDependencies<U extends AuthUser, A> {
  readonly users: UserStore<U>;
  readonly sessions: SessionManager<A>;
  readonly tokens: OneTimeTokens;
  readonly throttle: Throttle;
  readonly hasher: PasswordHasher;
  readonly policy: PasswordPolicy;
  readonly breachCheck: BreachChecker | undefined;
  readonly captcha: CaptchaVerifier | undefined;
  readonly mailer: Mailer;
  readonly audit: AuditSink | undefined;
  readonly hooks: HookLists<U, A>;
  readonly doors: Readonly<Partial<Record<Door, RateLimitRule>>>;
  readonly cookie: SessionCookieConfig;
  readonly attributeSchema: AttributeSchema<A> | undefined;
  readonly clock: Clock;
  readonly random: RandomSource;
  readonly logger: Logger;
  readonly metrics: Metrics;
}

type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;

export class AuthCore<U extends AuthUser, A> implements PluginContext<U, A> {
  readonly users: UserStore<U>;
  readonly sessions: SessionManager<A>;
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

  constructor(private readonly deps: CoreDependencies<U, A>) {
    this.users = deps.users;
    this.sessions = deps.sessions;
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
    this.metrics.count('auth_event', event.reason ? { type: event.type, reason: event.reason } : { type: event.type });
    if (!this.deps.audit) return;
    try {
      await this.deps.audit.emit(event, meta);
    } catch (error) {
      this.logger.error('Audit sink failed', { type: event.type, error: describe(error) });
    }
  }

  async mail(event: DistributiveOmit<AuthMailEvent, 'dedupeKey'>): Promise<void> {
    try {
      await this.deps.mailer.send({ ...event, dedupeKey: generateToken(this.random) } as AuthMailEvent);
    } catch (error) {
      this.logger.error('Mailer failed', { type: event.type, userId: event.userId, error: describe(error) });
    }
  }

  async rateLimit(door: Door, key: string, meta: RequestMeta | undefined): Promise<AuthFailure | null> {
    const rule = this.deps.doors[door] ?? DEFAULT_DOOR_LIMITS[door];
    const hit = await this.throttle.hit(`${door}:${key}`, rule);
    if (hit.allowed) return null;
    if (hit.firstRefusal) await this.emit({ type: 'rate_limit.exceeded', reason: door }, meta);
    return fail('rate_limited', `rate_limited:${door}`, { retryAfterSeconds: hit.retryAfterSeconds });
  }

  async checkCaptcha(door: CaptchaDoor, token: string | undefined, meta: RequestMeta): Promise<AuthFailure | null> {
    if (!this.deps.captcha) return null;
    const verdict = await this.deps.captcha.verify(token, { ip: meta.ip, door });
    this.metrics.count('auth_captcha', { door, verdict });
    if (verdict === 'pass') return null;
    return verdict === 'unavailable'
      ? fail('captcha_unavailable', 'captcha_unavailable')
      : fail('captcha_failed', 'captcha_rejected');
  }

  async verifyPassword(passwordHash: string | null | undefined, password: string): Promise<boolean> {
    // An oversized input is never a valid password; verify an empty one so the
    // hasher's cost stays bounded and the timing stays the same.
    const tooLong = checkPasswordPolicy(password, this.policy) === 'too_long';
    const normalized = tooLong ? '' : normalizePassword(password);
    if (!passwordHash || tooLong) {
      // Pay the same verify cost as a real account, and discard the result,
      // so even a preimage of the dummy hash can never authenticate.
      await this.hasher.verify(await dummyHashFor(this.hasher), normalized);
      return false;
    }
    return this.hasher.verify(passwordHash, normalized);
  }

  async hashNewPassword(password: string, meta: RequestMeta | undefined): Promise<AuthResult<string>> {
    const verdict = checkPasswordPolicy(password, this.policy);
    if (verdict === 'too_short') return fail('weak_password', 'password_too_short');
    if (verdict === 'too_long') return fail('password_too_long', 'password_too_long');
    const normalized = normalizePassword(password);
    if (this.deps.breachCheck) {
      const breach = await this.deps.breachCheck(normalized);
      this.metrics.count('auth_breach_check', { verdict: breach });
      if (breach === 'breached') return fail('breached_password', 'password_breached');
      if (breach === 'unavailable') {
        this.logger.warn('Breached-password check unavailable; accepting the password unchecked');
        await this.emit({ type: 'register.refused', reason: 'breach_check_unavailable', data: { accepted: true } }, meta).catch(() => undefined);
      }
    }
    return ok(await this.hasher.hash(normalized));
  }

  async issueSession(user: U, options: IssueOptions<A>): Promise<AuthResult<IssuedSession<A>>> {
    const inherited = options.inherit?.attributes;
    let merged: Record<string, unknown> = { ...(inherited as Record<string, unknown> | undefined) };
    for (const hook of this.hooks.sessionAttributes) {
      merged = { ...merged, ...(await hook({ user, via: options.via, inherited })) };
    }
    let attributes: A;
    try {
      attributes = this.deps.attributeSchema ? this.deps.attributeSchema.parse(merged) : (merged as A);
    } catch (error) {
      // A hook produced attributes the schema refuses: a bug in the app, never
      // something to mint a half-stamped session for.
      this.logger.error('Session attributes failed the schema at issue time', { userId: user.id, error: describe(error) });
      return fail('forbidden', 'invalid_session_attributes');
    }

    const refusal = await firstRefusal(this.hooks.beforeSessionCreate, { user, via: options.via, attributes, meta: options.meta });
    if (refusal) {
      await this.emit({ type: 'login.failure', userId: user.id, reason: refusal.reason, data: { via: options.via } }, options.meta);
      return fail(refusal.code, refusal.reason);
    }

    const rememberMe = options.rememberMe ?? options.inherit?.rememberMe ?? false;
    const persistentCookie = options.persistentCookie ?? options.inherit?.persistentCookie ?? rememberMe;
    const minted = await this.sessions.mint({
      userId: user.id,
      attributes,
      rememberMe,
      persistentCookie,
      authenticatedAt: options.authenticatedAt ?? this.clock.now(),
      meta: options.meta,
      ...(options.epoch === undefined ? {} : { epoch: options.epoch }),
    });
    if (!minted.ok) {
      await this.emit({ type: 'login.failure', userId: user.id, reason: minted.reason, data: { via: options.via } }, options.meta);
      return fail('session_expired', minted.reason);
    }
    // A grant: its audit row is written before the session is handed out.
    await this.emit({ type: 'session.created', userId: user.id, data: { via: options.via, rememberMe } }, options.meta);
    if (minted.evicted.length > 0) await this.notifyRevoked(user.id, minted.evicted, 'evicted');

    const cookie = createSessionCookie(this.cookie, minted.token, {
      expiresAt: minted.session.expiresAt,
      persistent: persistentCookie,
      now: this.clock.now(),
      origin: options.meta.origin,
    });
    return ok({ token: minted.token, session: minted.session, cookie });
  }

  async revokeAllSessions(userId: string, reason: RevocationReason): Promise<void> {
    const ids = await this.sessions.revokeAll(userId);
    await this.emit({ type: 'sessions.revoked', userId, reason }, undefined);
    await this.notifyRevoked(userId, ids, reason);
  }

  async notifyRevoked(userId: string, sessionIds: readonly string[], reason: RevocationReason): Promise<void> {
    for (const hook of this.hooks.onSessionsRevoked) {
      try {
        await hook({ userId, sessionIds, reason });
      } catch (error) {
        this.logger.error('onSessionsRevoked hook failed', { userId, reason, error: describe(error) });
      }
    }
  }
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
