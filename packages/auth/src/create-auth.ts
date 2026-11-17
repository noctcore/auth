/**
 * `createAuth` wires the stores and collaborators into the flows, checks the
 * configuration once at startup, and namespaces every plugin's flows under its
 * id. It returns functions, not HTTP handlers: your router calls them and maps
 * the results onto responses with `toPublicError`.
 */
import { AuthCore } from './core/auth-core';
import type { AuthConfig, AuthPlugin, PasswordResetJob } from './core/config';
import { mergeHooks } from './core/hooks';
import type { PluginContext } from './core/plugin-context';
import { checkPlugins, namespacePluginFlows, type PluginFlows } from './core/plugins';
import { deriveKey, toSecret } from './crypto/keys';
import { cryptoRandom } from './crypto/random';
import * as emailChange from './flows/email-change';
import * as verification from './flows/email-verification';
import { login, type LoginInput } from './flows/login';
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
import { deviceCookieName, parseCookieHeader, sessionCookieName } from './http/cookie';
import { DEFAULT_PASSWORD_POLICY } from './password/policy';
import { systemClock } from './ports/clock';
import { noopMetrics, silentLogger } from './ports/logger';
import type { AuthUser, SessionStore, StoredSession } from './ports/stores';
import { SessionManager } from './session/session-manager';
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

  checkPlugins(plugins, { captcha: Boolean(config.captcha) });

  const clock = config.clock ?? systemClock;
  const random = config.random ?? cryptoRandom;
  const logger = config.logger ?? silentLogger;
  const policy = { ...DEFAULT_PASSWORD_POLICY, ...config.password.policy };

  if (policy.minLength < 8)
    throw new AuthConfigError('password.policy.minLength must be at least 8');

  const cookie = config.session?.cookie ?? {};

  // Validates the cookie config now rather than on the first sign-in.
  sessionCookieName(cookie);

  const sessions = new SessionManager<A>(
    config.stores.sessions,
    config.session ?? {},
    clock,
    random,
    logger,
  );

  assertStoreOutlivesSessions(config.stores.sessions, sessions);

  const core = new AuthCore<U, A>({
    users: config.stores.users,
    sessions,
    tokens: new OneTimeTokens(config.stores.tokens, clock, random, codeKey),
    throttle: new Throttle(config.stores.counters, clock, config.throttle?.lockout),
    hasher: config.password.hasher,
    policy,
    breachCheck: config.password.breachCheck || undefined,
    captcha: config.captcha,
    mailer: config.mailer,
    audit: config.audit,
    hooks: mergeHooks<U, A>([...plugins.map((p) => p.hooks), config.hooks]),
    doors: config.throttle?.doors ?? {},
    cookie,
    attributeSchema: config.session?.attributes,
    deviceKey,
    pluginKey,
    freshAuthAgeMs: settings.freshAuthAgeMs,
    clock,
    random,
    logger,
    metrics: config.metrics ?? noopMetrics,
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
    }) => verification.verifyEmailLink(core, input),
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
    sessions: {
      list: (session: StoredSession<A>) => listSessions(core, session),
      revoke: (input: { session: StoredSession<A>; id: string; meta: RequestMeta }) =>
        revokeSession(core, settings, input),
      revokeOthers: (input: { session: StoredSession<A>; meta: RequestMeta }) =>
        revokeOtherSessions(core, settings, input),
      revokeAll: (input: { session: StoredSession<A>; meta: RequestMeta }) =>
        revokeAllSessions(core, input),
    },
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
