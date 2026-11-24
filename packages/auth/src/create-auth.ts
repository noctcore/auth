/**
 * `createAuth` wires the stores and collaborators into the flows, checks the
 * configuration once at startup, and namespaces every plugin's flows under its
 * id. It returns functions, not HTTP handlers: your router calls them and maps
 * the results onto responses with `toPublicError`.
 */
import { AuthCore } from './core/auth-core';
import { BackgroundTasks } from './core/background';
import { toMilliseconds, type Duration } from './shared/duration';
import type { AuthConfig, AuthPlugin, Door, PasswordResetJob } from './core/config';
import { mergeHooks } from './core/hooks';
import type { PluginContext } from './core/plugin-context';
import { checkPlugins, namespacePluginFlows, type PluginFlows } from './core/plugins';
import { deriveKeys, toPreviousSecrets, toSecret } from './crypto/keys';
import { cryptoRandom } from './crypto/random';
import * as emailChange from './flows/email-change';
import { clearEmailRevertLockout, lockoutHooks } from './flows/email-lockout';
import { heldAccount, isAddressHeld } from './flows/email-reservation';
import * as verification from './flows/email-verification';
import { sendLockNotice } from './flows/lock-notice';
import { login, type LoginInput } from './flows/login';
import { clearLock, inspectLock, type LockTarget } from './flows/lockout-admin';
import { permanentLockHooks } from './flows/permanent-lock';
import { changePassword, reauthenticate } from './flows/password-change';
import {
  inspectPasswordReset,
  resetPassword,
  verifyPasswordResetCode,
} from './flows/password-reset';
import { processPasswordReset, requestPasswordReset } from './flows/password-reset-request';
import { register, type RegisterInput } from './flows/register';
import { resolveSettings } from './flows/resolve-settings';
import {
  listSessions,
  logout,
  revokeAllSessions,
  revokeOtherSessions,
  revokeSession,
} from './flows/session-management';
import { guardedMetrics } from './core/guarded-metrics';
import { requireFreshAuth, validateRequest } from './flows/session-validation';
import {
  deviceCookieName,
  parseCookieHeader,
  resolveSameSite,
  sessionCookieName,
} from './http/cookie';
import { DEFAULT_PASSWORD_POLICY } from './password/policy';
import { systemClock } from './ports/clock';
import { noopMetrics, silentLogger } from './ports/logger';
import type { AuthUser, SessionStore, StoredSession } from './ports/stores';
import { SessionManager } from './session/session-manager';
import { assertBoolean, assertString } from './shared/config-checks';
import { resolveEmailNormalizer } from './shared/email';
import { AuthConfigError } from './shared/errors';
import type { RequestMeta } from './shared/meta';
import { DEVICE_CLOCK_SKEW_MS } from './shared/clock-skew';
import { assertWindowRule, type RateLimitRule } from './throttle/rules';
import { Throttle } from './throttle/throttle';
import { OneTimeTokens } from './tokens/one-time-tokens';

function assertRequiredConfig<U extends AuthUser, A, P extends readonly AuthPlugin[]>(
  config: AuthConfig<U, A, P>,
): void {
  const { stores } = config;

  if (!stores?.users || !stores.sessions || !stores.tokens || !stores.counters) {
    throw new AuthConfigError(
      'stores.users, stores.sessions, stores.tokens and stores.counters are required',
    );
  }

  if (!config.password?.hasher) throw new AuthConfigError('password.hasher is required');
  if (!config.mailer) throw new AuthConfigError('mailer is required');

  assertOptionalPorts(config);
}

/**
 * Two optional collaborators read by truthiness: a string such as "false"
 * from the environment would count as configured, and the first sign-up or
 * login would throw calling it instead of the app refusing to start.
 */
function assertOptionalPorts<U extends AuthUser, A, P extends readonly AuthPlugin[]>(
  config: AuthConfig<U, A, P>,
): void {
  const breachCheck: unknown = config.password.breachCheck;

  if (
    breachCheck !== undefined &&
    breachCheck !== null &&
    breachCheck !== false &&
    typeof breachCheck !== 'function'
  )
    throw new AuthConfigError(
      'password.breachCheck must be a breach checker, such as pwnedPasswords(), or false',
    );

  const captcha: unknown = config.captcha;

  if (
    captcha !== undefined &&
    captcha !== null &&
    typeof (captcha as { verify?: unknown }).verify !== 'function'
  )
    throw new AuthConfigError('captcha must be a captcha verifier, such as turnstile({ ... })');
}

/** A limit the session store declares, refused unless it is a positive number (fail closed). */
function declaredLimit(
  store: SessionStore,
  field: 'maxSessionTtlMs' | 'epochTtlMs',
): number | undefined {
  const value: unknown = store[field];

  if (value === undefined) return undefined;

  if (typeof value !== 'number' || !(value > 0))
    throw new AuthConfigError(`The session store's ${field} must be a positive number of ms`);

  return value;
}

/** Refuses session lifetimes longer than the store promises to keep its revocation fence. */
function assertStoreOutlivesSessions<A>(store: SessionStore, sessions: SessionManager<A>): void {
  const storeLimit = declaredLimit(store, 'maxSessionTtlMs');
  const longest = Math.max(sessions.absoluteTtlMs, sessions.rememberMeTtlMs);

  if (storeLimit !== undefined && longest > storeLimit) {
    throw new AuthConfigError(
      `The session store guards sessions up to ${storeLimit} ms, but sessions may last ${longest} ms: raise the store's maxSessionTtl or lower session.rememberMeTtl`,
    );
  }
}

/** The keys of `options` whose value is neither undefined nor null, so a spread over defaults keeps them. */
function definedKeys<T extends object>(options: T | undefined): Partial<T> {
  return Object.fromEntries(
    Object.entries(options ?? {}).filter(([, value]) => value !== undefined && value !== null),
  ) as Partial<T>;
}

/** Each configured door rule, checked now rather than on the first request at that door. */
function checkedDoors(
  doors: Partial<Record<Door, RateLimitRule>>,
): Partial<Record<Door, RateLimitRule>> {
  for (const [door, rule] of Object.entries(doors) as [Door, RateLimitRule | null | undefined][]) {
    // Left out or null: the door reads its default (`DEFAULT_DOOR_LIMITS`).
    if (rule === undefined || rule === null) continue;

    const name = `throttle.doors.${door}`;
    let windowMs: number;

    try {
      windowMs = toMilliseconds(rule.window);
    } catch {
      throw new AuthConfigError(`${name}.window must be a duration`);
    }

    // A door rule has no default limit to fall back on: a missing one is refused too.
    assertWindowRule(name, { limit: rule.limit ?? Number.NaN, windowMs });
  }

  return doors;
}

/**
 * Refuses a device token that could outlive the store's epoch: the epoch is
 * the token's only revocation fence, and a lapsed epoch reads as 0 again, so a
 * revoked token would verify once more. The token's `issuedAt` comes from the
 * issuing server's clock and may sit up to `DEVICE_CLOCK_SKEW_MS` ahead, so
 * the max age plus that margin must fit inside the epoch TTL.
 */
function assertStoreOutlivesDeviceTokens(store: SessionStore, deviceMaxAgeMs: number): void {
  const epochLimit = declaredLimit(store, 'epochTtlMs');

  if (epochLimit !== undefined && deviceMaxAgeMs + DEVICE_CLOCK_SKEW_MS > epochLimit) {
    throw new AuthConfigError(
      `The session store keeps a revocation epoch for ${epochLimit} ms, but device tokens may last ${deviceMaxAgeMs} ms plus ${DEVICE_CLOCK_SKEW_MS} ms of clock skew: lower throttle.lockout.deviceMaxAge or raise the store's epochTtl`,
    );
  }
}

export function createAuth<
  U extends AuthUser,
  A = Record<string, never>,
  const P extends readonly AuthPlugin[] = [],
>(config: AuthConfig<U, A, P>) {
  assertRequiredConfig(config);

  const settings = resolveSettings(config);
  const secret = toSecret(config.secret);

  // The current secret first: it alone signs and stores, the previous ones only verify.
  const secrets: [Uint8Array, ...Uint8Array[]] = [
    secret,
    ...toPreviousSecrets(config.previousSecret, secret),
  ];

  const plugins = (config.plugins ?? []) as readonly AuthPlugin[];
  // One secret, a separate key per use: a code HMAC can never double as a device token.
  const codeKeys = deriveKeys(secrets, 'codes');
  const deviceKeys = deriveKeys(secrets, 'device');
  const pluginKeys = deriveKeys(secrets, 'plugins');
  const handleKeys = deriveKeys(secrets, 'session-handles');

  checkPlugins(plugins, { captcha: Boolean(config.captcha) });

  const clock = config.clock ?? systemClock;
  const random = config.random ?? cryptoRandom;
  const logger = config.logger ?? silentLogger;
  const appMetrics = config.metrics ?? noopMetrics;
  // A port that throws is logged, never thrown into a flow (guarded-metrics.ts).
  const metrics = guardedMetrics(appMetrics, logger);
  const background = new BackgroundTasks(logger, metrics, config.background);

  const emails = resolveEmailNormalizer(config.email?.normalize, (message, details) =>
    logger.error(message, details ?? {}),
  );

  // A key left out, undefined or null keeps its default instead of overwriting it.
  const policy = { ...DEFAULT_PASSWORD_POLICY, ...definedKeys(config.password.policy) };

  // `NaN` passes every comparison: a `NaN` minimum would accept an empty password.
  if (!Number.isSafeInteger(policy.minLength))
    throw new AuthConfigError('password.policy.minLength must be a whole number');

  if (policy.minLength < 8)
    throw new AuthConfigError('password.policy.minLength must be at least 8');

  // And a `NaN` or infinite maximum would bound nothing.
  if (!Number.isSafeInteger(policy.maxLength) || policy.maxLength < policy.minLength) {
    throw new AuthConfigError(
      'password.policy.maxLength must be a whole number of at least password.policy.minLength',
    );
  }

  const cookie = config.session?.cookie ?? {};

  // A string "false" would read as on here, and as a different cookie name.
  assertBoolean('session.cookie.secure', cookie.secure);
  assertString('session.cookie.name', cookie.name);

  // Validates the cookie name now rather than on the first sign-in, and refuses
  // a fixed `SameSite=None` without Secure at boot. A function-valued SameSite
  // cannot be checked without a request, so it is checked by `resolveSameSite`
  // when a cookie is built.
  sessionCookieName(cookie);

  if (typeof cookie.sameSite !== 'function') resolveSameSite(cookie, undefined);

  const sessions = new SessionManager<A>(
    config.stores.sessions,
    config.session ?? {},
    clock,
    random,
    logger,
  );

  assertStoreOutlivesSessions(config.stores.sessions, sessions);

  const tokens = new OneTimeTokens(config.stores.tokens, clock, random, codeKeys);

  const throttle = new Throttle(config.stores.counters, clock, config.throttle?.lockout);

  assertStoreOutlivesDeviceTokens(config.stores.sessions, throttle.deviceMaxAgeMs);

  // Only a store that can change emails can have an account in revert lockout.
  // A permanent lock without trusted devices refuses every session for the account.
  const coreHooks = [
    ...(typeof config.stores.users.changeEmail === 'function' ? [lockoutHooks(tokens)] : []),
    ...(throttle.permanentTier && !throttle.permanentDevices ? [permanentLockHooks(throttle)] : []),
  ];

  const core: AuthCore<U, A> = new AuthCore<U, A>({
    users: config.stores.users,
    sessions,
    tokens,
    throttle,
    hasher: config.password.hasher,
    policy,
    breachCheck: config.password.breachCheck || undefined,
    captcha: config.captcha,
    mailer: config.mailer,
    audit: config.audit,
    hooks: mergeHooks<U, A>([...coreHooks, ...plugins.map((p) => p.hooks), config.hooks]),
    doors: checkedDoors(config.throttle?.doors ?? {}),
    cookie,
    attributeSchema: config.session?.attributes,
    emails,
    deviceKeys,
    handleKeys,
    pluginKeys,
    freshAuthAgeMs: settings.freshAuthAgeMs,
    clock,
    random,
    logger,
    metrics,
    background,
    addressHeld: async (email) =>
      (await heldAccount({ tokens, users: config.stores.users }, email)) !== null,
    // Called only once `core` exists (a lock is reported by a flow).
    announceLock: (owner, lock, meta): Promise<void> =>
      sendLockNotice(core, owner, lock, meta, true),
  });

  const flows = {
    /** The name of the session cookie (`__Host-session` by default). */
    cookieName: sessionCookieName(cookie),
    /** Reads the session token out of a `Cookie` header. */
    readSessionToken: (cookieHeader: string | null | undefined) =>
      parseCookieHeader(cookieHeader).get(sessionCookieName(cookie)) ?? null,
    /** The name of the trusted-device cookie. */
    deviceCookieName: deviceCookieName(cookie),
    /** Reads the trusted-device token out of a `Cookie` header, for `login({ deviceToken })`. */
    readDeviceToken: (cookieHeader: string | null | undefined) =>
      parseCookieHeader(cookieHeader).get(deviceCookieName(cookie)) ?? null,
    register: (input: RegisterInput) => register(core, settings, input),
    login: (input: LoginInput) => login(core, input),
    logout: (input: { token: string | null | undefined; meta: RequestMeta }) => logout(core, input),
    validateRequest: (input: {
      token: string | null | undefined;
      meta?: RequestMeta;
      touch?: boolean;
    }) => validateRequest(core, input),
    requireFreshAuth: (session: StoredSession<A>) => requireFreshAuth(core, settings, session),
    reauthenticate: (input: { session: StoredSession<A>; password: string; meta: RequestMeta }) =>
      reauthenticate(core, input),
    requestEmailVerification: (input: { session: StoredSession<A>; meta: RequestMeta }) =>
      verification.requestEmailVerification(core, settings, input),
    verifyEmailCode: (input: { session: StoredSession<A>; code: string; meta: RequestMeta }) =>
      verification.verifyEmailCode(core, settings, input),
    verifyEmailLink: (input: {
      token: string;
      session: StoredSession<A> | null;
      meta: RequestMeta;
    }) => verification.verifyEmailLink(core, settings, input),
    requestPasswordReset: (input: { email: string; captchaToken?: string; meta: RequestMeta }) =>
      requestPasswordReset(core, settings, input),
    verifyPasswordResetCode: (input: { email: string; code: string; meta: RequestMeta }) =>
      verifyPasswordResetCode(core, settings, input),
    /**
     * Checks a reset link (a ticket in code mode) without spending it, for a
     * reset page on load: the account, the expiry and whether `resetPassword`
     * will ask for a second factor. Counted on the `password-reset` door.
     */
    inspectPasswordReset: (input: { token: string; meta: RequestMeta }) =>
      inspectPasswordReset(core, settings, input),
    resetPassword: (input: {
      token: string;
      password: string;
      secondFactor?: string;
      meta: RequestMeta;
    }) => resetPassword(core, settings, input),
    changePassword: (input: {
      session: StoredSession<A>;
      currentPassword: string;
      newPassword: string;
      secondFactor?: string;
      meta: RequestMeta;
    }) => changePassword(core, input),
    /** Starts an email change: fresh authentication (and a step-up with a factor), then a code to the new address. */
    requestEmailChange: (input: emailChange.RequestEmailChangeInput<A>) =>
      emailChange.requestEmailChange(core, settings, input),
    /** Confirms an email change with the code, in a signed-in session of the same account. */
    confirmEmailChangeCode: (input: {
      session: StoredSession<A>;
      code: string;
      meta: RequestMeta;
    }) => emailChange.confirmEmailChangeCode(core, settings, input),
    /** Confirms an email change with the link, in a signed-in session of the same account. */
    confirmEmailChangeLink: (input: {
      token: string;
      session: StoredSession<A> | null;
      meta: RequestMeta;
    }) => emailChange.confirmEmailChangeLink(core, settings, input),
    /** Undoes an email change from the link mailed to the old address. No session needed. */
    revertEmailChange: (input: { token: string; meta: RequestMeta }) =>
      emailChange.revertEmailChange(core, settings, input),
    /**
     * Whether an address is held for an account whose email change away from
     * it can still be reverted. Every path of your app that creates a user or
     * gives one an address (invites, admin create, a first SSO login, imports)
     * must refuse a held address as it refuses a taken one.
     */
    isAddressHeld: (email: string) => isAddressHeld(core, email),
    /**
     * The address as the configured `email.normalize` policy spells it, or
     * null when the policy refuses it. Use it wherever your own code stores
     * or looks up an address, so it matches what the flows store.
     */
    normalizeEmail: (email: unknown) => core.normalizeEmail(email),
    /**
     * Ends the lockout left by a revert that could not restore the address,
     * and voids the owner's revert link and the hold on the old address with
     * it. For support, once the account is on an address its owner controls.
     */
    clearEmailRevertLockout: (input: { userId: string; meta: RequestMeta }) =>
      clearEmailRevertLockout(core, input),
    /**
     * Admin tools for the login lockout. Admin-only routes: they answer for
     * any address, so a public route would reveal which addresses are locked.
     */
    lockout: {
      /** An address's (or an account's) lock state: temporary, permanent or none. */
      inspect: (target: LockTarget) => inspectLock(core, target),
      /**
       * Lifts every lock, the permanent tier included, and resets the backoff.
       * Returns the state it found; audits `account.lock_cleared` when it lifted one.
       */
      clear: (input: LockTarget & { meta: RequestMeta }) => clearLock(core, input),
    },
    sessions: {
      /** The caller's live sessions, newest activity first, each named by its public `handle`. */
      list: (session: StoredSession<A>) => listSessions(core, session),
      /**
       * Revokes the caller's session with this `handle` (from `list`). Another
       * device's session needs fresh authentication. A handle that names no
       * session of the caller, another user's included, answers `{ revoked: false }`.
       */
      revoke: (input: { session: StoredSession<A>; handle: string; meta: RequestMeta }) =>
        revokeSession(core, settings, input),
      /**
       * The public handle of a session id (`session.id`, or an id from
       * `onSessionsRevoked`), to match it against the handles `list` showed.
       */
      handle: (sessionId: string) => core.sessionHandle(sessionId),
      revokeOthers: (input: { session: StoredSession<A>; meta: RequestMeta }) =>
        revokeOtherSessions(core, settings, input),
      revokeAll: (input: { session: StoredSession<A>; meta: RequestMeta }) =>
        revokeAllSessions(core, input),
    },
    /**
     * Resolves once no background task (mail, audit writes off the response
     * path, detached reset jobs) is left running, tasks started while it waits
     * included. Never rejects. Await it on graceful shutdown. With `timeout`
     * it gives up after that long and logs what it left running, so a send
     * that never settles cannot hold shutdown forever.
     */
    flush: (options?: { readonly timeout?: Duration }) => background.flush(options),
    /** Entry points for your queue workers. */
    jobs: {
      processPasswordReset: (job: PasswordResetJob) => processPasswordReset(core, settings, job),
    },
    /** For plugins and advanced integrations: the same steps the core flows use. */
    context: core as PluginContext<U, A>,
  };

  const namespaced = namespacePluginFlows(plugins, flows, core);

  return Object.assign(flows, namespaced) as typeof flows & PluginFlows<P>;
}

export type Auth<U extends AuthUser, A, P extends readonly AuthPlugin[] = []> = ReturnType<
  typeof createAuth<U, A, P>
>;
