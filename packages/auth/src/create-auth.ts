/**
 * `createAuth` wires the stores and collaborators into the flows, checks the
 * configuration once at startup, and namespaces every plugin's flows under its
 * id. It returns functions, not HTTP handlers: your router calls them and maps
 * the results onto responses with `toPublicError`.
 */
import { AuthCore } from './core/auth-core';
import { BackgroundTasks } from './core/background';
import type { Duration } from './shared/duration';
import type { AuthConfig, AuthPlugin, PasswordResetJob } from './core/config';
import { mergeHooks } from './core/hooks';
import type { PluginContext } from './core/plugin-context';
import { checkPlugins, namespacePluginFlows, type PluginFlows } from './core/plugins';
import { deriveKey, toSecret } from './crypto/keys';
import { cryptoRandom } from './crypto/random';
import * as emailChange from './flows/email-change';
import { clearEmailRevertLockout, lockoutHooks } from './flows/email-lockout';
import { isAddressHeld } from './flows/email-reservation';
import * as verification from './flows/email-verification';
import { login, type LoginInput } from './flows/login';
import { clearLock, inspectLock, type LockTarget } from './flows/lockout-admin';
import { permanentLockHooks } from './flows/permanent-lock';
import { changePassword, reauthenticate } from './flows/password-change';
import { resetPassword, verifyPasswordResetCode } from './flows/password-reset';
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
import { resolveEmailNormalizer } from './shared/email';
import { AuthConfigError } from './shared/errors';
import type { RequestMeta } from './shared/meta';
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
}

/** Refuses session lifetimes longer than the store promises to keep its revocation fence. */
function assertStoreOutlivesSessions<A>(store: SessionStore, sessions: SessionManager<A>): void {
  const storeLimit = store.maxSessionTtlMs;
  const longest = Math.max(sessions.absoluteTtlMs, sessions.rememberMeTtlMs);

  if (storeLimit !== undefined && longest > storeLimit) {
    throw new AuthConfigError(
      `The session store guards sessions up to ${storeLimit} ms, but sessions may last ${longest} ms: raise the store's maxSessionTtl or lower session.rememberMeTtl`,
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
  const plugins = (config.plugins ?? []) as readonly AuthPlugin[];
  // One secret, a separate key per use: a code HMAC can never double as a device token.
  const codeKey = deriveKey(secret, 'codes');
  const deviceKey = deriveKey(secret, 'device');
  const pluginKey = deriveKey(secret, 'plugins');
  const handleKey = deriveKey(secret, 'session-handles');

  checkPlugins(plugins, { captcha: Boolean(config.captcha) });

  const clock = config.clock ?? systemClock;
  const random = config.random ?? cryptoRandom;
  const logger = config.logger ?? silentLogger;
  const metrics = config.metrics ?? noopMetrics;
  const background = new BackgroundTasks(logger, metrics, config.background);

  const emails = resolveEmailNormalizer(config.email?.normalize, (message, details) =>
    logger.error(message, details ?? {}),
  );

  const policy = { ...DEFAULT_PASSWORD_POLICY, ...config.password.policy };

  if (policy.minLength < 8)
    throw new AuthConfigError('password.policy.minLength must be at least 8');

  const cookie = config.session?.cookie ?? {};

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

  const tokens = new OneTimeTokens(config.stores.tokens, clock, random, codeKey);

  const throttle = new Throttle(config.stores.counters, clock, config.throttle?.lockout);

  // Only a store that can change emails can have an account in revert lockout.
  // A permanent lock without trusted devices refuses every session for the account.
  const coreHooks = [
    ...(typeof config.stores.users.changeEmail === 'function' ? [lockoutHooks(tokens)] : []),
    ...(throttle.permanentTier && !throttle.permanentDevices ? [permanentLockHooks(throttle)] : []),
  ];

  const core = new AuthCore<U, A>({
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
    doors: config.throttle?.doors ?? {},
    cookie,
    attributeSchema: config.session?.attributes,
    emails,
    deviceKey,
    handleKey,
    pluginKey,
    freshAuthAgeMs: settings.freshAuthAgeMs,
    clock,
    random,
    logger,
    metrics,
    background,
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
