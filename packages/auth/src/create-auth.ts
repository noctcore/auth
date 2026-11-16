/**
 * `createAuth` wires the stores and collaborators into the flows, checks the
 * configuration once at startup, and namespaces every plugin's flows under its
 * id. It returns functions, not HTTP handlers: your router calls them and maps
 * the results onto responses with `toPublicError`.
 */
import { systemClock } from './clock';
import type { AuthConfig, AuthPlugin, PasswordResetJob } from './config';
import { AuthCore } from './core';
import { deviceCookieName, parseCookieHeader, sessionCookieName } from './cookie';
import { hmacSha256Hex } from './hash';
import { toMilliseconds } from './duration';
import { AuthConfigError } from './errors';
import { mergeHooks } from './hooks';
import { silentLogger, noopMetrics } from './logger';
import { DEFAULT_PASSWORD_POLICY } from './password/policy';
import { cryptoRandom } from './random';
import { SessionManager } from './session';
import type { AuthUser, StoredSession } from './stores';
import { Throttle } from './throttle';
import { OneTimeTokens } from './tokens';
import * as account from './flows/account';
import * as verification from './flows/email-verification';
import { login, type LoginInput } from './flows/login';
import * as reset from './flows/password-reset';
import { register, type RegisterInput } from './flows/register';
import type { FlowSettings } from './flows/settings';
import type { PluginContext } from './plugin-context';
import type { RequestMeta } from './meta';

const MIN_SECRET_BYTES = 32;

function deriveKey(secret: Uint8Array, purpose: string): Uint8Array {
  return new TextEncoder().encode(hmacSha256Hex(secret, `noctcore-auth:${purpose}`));
}

type UnionToIntersection<T> = (T extends unknown ? (value: T) => void : never) extends (value: infer I) => void ? I : never;

/** `{ [plugin id]: plugin flows }` for the configured plugins. */
export type PluginFlows<P extends readonly AuthPlugin[]> = UnionToIntersection<
  P[number] extends infer Plugin
    ? Plugin extends AuthPlugin<infer Id, infer F>
      ? { readonly [K in Id]: F }
      : never
    : never
>;

function toSecret(secret: Uint8Array | string | undefined): Uint8Array {
  if (secret === undefined) throw new AuthConfigError('secret is required (32 bytes or more)');
  const bytes = typeof secret === 'string' ? new TextEncoder().encode(secret) : secret;
  if (bytes.byteLength < MIN_SECRET_BYTES) throw new AuthConfigError(`secret must be at least ${MIN_SECRET_BYTES} bytes`);
  return bytes;
}

function resolveSettings<U extends AuthUser, A, P extends readonly AuthPlugin[]>(config: AuthConfig<U, A, P>): FlowSettings {
  const verificationKind = config.emailVerification?.kind ?? 'code';
  const resetKind = config.passwordReset?.kind ?? 'link';
  const settings: FlowSettings = {
    revealExisting: config.registration?.revealExisting ?? false,
    autoLogin: config.registration?.autoLogin ?? false,
    verification: {
      kind: verificationKind,
      ttlMs: toMilliseconds(config.emailVerification?.ttl ?? (verificationKind === 'code' ? '15m' : '24h')),
      digits: config.emailVerification?.digits ?? 8,
      maxAttempts: config.emailVerification?.maxAttempts ?? 5,
    },
    reset: {
      kind: resetKind,
      ttlMs: toMilliseconds(config.passwordReset?.ttl ?? (resetKind === 'code' ? '15m' : '1h')),
      digits: config.passwordReset?.digits ?? 8,
      maxAttempts: config.passwordReset?.maxAttempts ?? 5,
      ticketTtlMs: toMilliseconds(config.passwordReset?.ticketTtl ?? '10m'),
      markEmailVerified: config.passwordReset?.markEmailVerified ?? true,
      enqueue: config.passwordReset?.enqueue,
    },
    urls: { verifyEmail: config.urls?.verifyEmail, resetPassword: config.urls?.resetPassword },
    freshAuthAgeMs: toMilliseconds(config.session?.freshAuthAge ?? '10m'),
  };
  if (settings.autoLogin && !settings.revealExisting) {
    throw new AuthConfigError('registration.autoLogin requires registration.revealExisting: a session would reveal that the account is new');
  }
  if (verificationKind === 'link' && !settings.urls.verifyEmail) throw new AuthConfigError('urls.verifyEmail is required for link verification');
  if (resetKind === 'link' && !settings.urls.resetPassword) throw new AuthConfigError('urls.resetPassword is required for link resets');
  for (const [name, digits] of [
    ['emailVerification.digits', settings.verification.digits],
    ['passwordReset.digits', settings.reset.digits],
  ] as const) {
    if (!Number.isInteger(digits) || digits < 6 || digits > 9) throw new AuthConfigError(`${name} must be 6 to 9`);
  }
  return settings;
}

export function createAuth<U extends AuthUser, A = Record<string, never>, const P extends readonly AuthPlugin[] = []>(
  config: AuthConfig<U, A, P>,
) {
  if (!config.stores?.users || !config.stores.sessions || !config.stores.tokens || !config.stores.counters) {
    throw new AuthConfigError('stores.users, stores.sessions, stores.tokens and stores.counters are required');
  }
  if (!config.password?.hasher) throw new AuthConfigError('password.hasher is required');
  if (!config.mailer) throw new AuthConfigError('mailer is required');

  const settings = resolveSettings(config);
  const secret = toSecret(config.secret);
  const plugins = (config.plugins ?? []) as readonly AuthPlugin[];
  // One secret, a separate key per use: a code HMAC can never double as a device token.
  const codeKey = deriveKey(secret, 'codes');
  const deviceKey = deriveKey(secret, 'device');
  const seen = new Set<string>();
  for (const plugin of plugins) {
    if (seen.has(plugin.id)) throw new AuthConfigError(`Duplicate plugin id: ${plugin.id}`);
    seen.add(plugin.id);
    if (plugin.requires?.includes('captcha') && !config.captcha) throw new AuthConfigError(`Plugin ${plugin.id} requires a captcha`);
  }

  const clock = config.clock ?? systemClock;
  const random = config.random ?? cryptoRandom;
  const logger = config.logger ?? silentLogger;
  const policy = { ...DEFAULT_PASSWORD_POLICY, ...config.password.policy };
  if (policy.minLength < 8) throw new AuthConfigError('password.policy.minLength must be at least 8');
  const cookie = config.session?.cookie ?? {};
  sessionCookieName(cookie);

  const core = new AuthCore<U, A>({
    users: config.stores.users,
    sessions: new SessionManager<A>(config.stores.sessions, config.session ?? {}, clock, random, logger),
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
    clock,
    random,
    logger,
    metrics: config.metrics ?? noopMetrics,
  });

  const flows = {
    /** The name of the session cookie (`__Host-session` by default). */
    cookieName: sessionCookieName(cookie),
    /** Reads the session token out of a `Cookie` header. */
    readSessionToken: (cookieHeader: string | null | undefined) => parseCookieHeader(cookieHeader).get(sessionCookieName(cookie)) ?? null,
    /** The name of the trusted-device cookie. */
    deviceCookieName: deviceCookieName(cookie),
    /** Reads the trusted-device token out of a `Cookie` header, for `login({ deviceToken })`. */
    readDeviceToken: (cookieHeader: string | null | undefined) => parseCookieHeader(cookieHeader).get(deviceCookieName(cookie)) ?? null,
    register: (input: RegisterInput) => register(core, settings, input),
    login: (input: LoginInput) => login(core, input),
    logout: (input: { token: string | null | undefined; meta: RequestMeta }) => account.logout(core, input),
    validateRequest: (input: { token: string | null | undefined; meta?: RequestMeta; touch?: boolean }) =>
      account.validateRequest(core, input),
    requireFreshAuth: (session: StoredSession<A>) => account.requireFreshAuth(core, settings, session),
    reauthenticate: (input: { session: StoredSession<A>; password: string; meta: RequestMeta }) => account.reauthenticate(core, input),
    requestEmailVerification: (input: { session: StoredSession<A>; meta: RequestMeta }) =>
      verification.requestEmailVerification(core, settings, input),
    verifyEmailCode: (input: { session: StoredSession<A>; code: string; meta: RequestMeta }) =>
      verification.verifyEmailCode(core, settings, input),
    verifyEmailLink: (input: { token: string; session: StoredSession<A> | null; meta: RequestMeta }) =>
      verification.verifyEmailLink(core, input),
    requestPasswordReset: (input: { email: string; captchaToken?: string; meta: RequestMeta }) =>
      reset.requestPasswordReset(core, settings, input),
    verifyPasswordResetCode: (input: { email: string; code: string; meta: RequestMeta }) =>
      reset.verifyPasswordResetCode(core, settings, input),
    resetPassword: (input: { token: string; password: string; secondFactor?: string; meta: RequestMeta }) =>
      reset.resetPassword(core, settings, input),
    changePassword: (input: {
      session: StoredSession<A>;
      currentPassword: string;
      newPassword: string;
      secondFactor?: string;
      meta: RequestMeta;
    }) => account.changePassword(core, input),
    sessions: {
      list: (session: StoredSession<A>) => account.listSessions(core, session),
      revoke: (input: { session: StoredSession<A>; id: string; meta: RequestMeta }) => account.revokeSession(core, settings, input),
      revokeOthers: (input: { session: StoredSession<A>; meta: RequestMeta }) => account.revokeOtherSessions(core, settings, input),
      revokeAll: (input: { session: StoredSession<A>; meta: RequestMeta }) => account.revokeAllSessions(core, input),
    },
    /** Entry points for your queue workers. */
    jobs: {
      processPasswordReset: (job: PasswordResetJob) => reset.processPasswordReset(core, settings, job),
    },
    /** For plugins and advanced integrations: the same steps the core flows use. */
    context: core as PluginContext<U, A>,
  };

  const namespaced: Record<string, object> = {};
  for (const plugin of plugins) {
    if (plugin.id in flows) throw new AuthConfigError(`Plugin id ${plugin.id} collides with a core flow`);
    if (plugin.flows) namespaced[plugin.id] = plugin.flows(core);
  }
  return Object.assign(flows, namespaced) as typeof flows & PluginFlows<P>;
}

export type Auth<U extends AuthUser, A, P extends readonly AuthPlugin[] = []> = ReturnType<typeof createAuth<U, A, P>>;

/** Defines a plugin with its id and flows typed. */
export function definePlugin<const Id extends string, F extends object>(plugin: AuthPlugin<Id, F>): AuthPlugin<Id, F> {
  return plugin;
}
