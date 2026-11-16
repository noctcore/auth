/**
 * @noctcore/auth: the framework-free core.
 *
 * Primitives in this entry point: randomness, hashing, email normalisation,
 * password policy, the hasher contract and the breached-password check,
 * cookies, CSRF, captcha, client IP resolution, durations, results and errors.
 * Argon2id lives in `@noctcore/auth/argon2` so its native dependency stays
 * optional.
 */
export { systemClock, type Clock } from './clock';
export { toMilliseconds, toSeconds, type Duration } from './duration';
export { noopMetrics, silentLogger, type Logger, type Metrics } from './logger';
export type { RequestMeta } from './meta';
export {
  cryptoRandom,
  generateNumericCode,
  generateToken,
  isTokenShape,
  randomBytes,
  TOKEN_BYTES,
  type RandomSource,
} from './random';
export { hexDigestsEqual, hmacSha256Hex, secretsEqual, sha256Hex } from './hash';
export { normalizeEmail, type NormalizedEmail } from './email';
export {
  AuthConfigError,
  fail,
  ok,
  toPublicError,
  type AuthErrorCode,
  type AuthFailure,
  type AuthResult,
  type AuthSuccess,
} from './errors';
export {
  checkPasswordPolicy,
  DEFAULT_PASSWORD_POLICY,
  normalizePassword,
  type PasswordPolicy,
  type PasswordPolicyVerdict,
} from './password/policy';
export { dummyHashFor, type PasswordHasher } from './password/hasher';
export {
  pwnedPasswords,
  type BreachChecker,
  type BreachVerdict,
  type PwnedPasswordsOptions,
} from './password/breach';
export {
  createBlankSessionCookie,
  createSessionCookie,
  parseCookieHeader,
  serializeCookie,
  sessionCookieName,
  type CookieAttributes,
  type CookieSpec,
  type SameSite,
  type SessionCookieConfig,
} from './cookie';
export { createCsrfToken, verifyCsrfToken, verifyFetchSite, verifyRequestOrigin } from './csrf';
export {
  turnstile,
  type CaptchaDoor,
  type CaptchaVerdict,
  type CaptchaVerifier,
  type TurnstileOptions,
} from './captcha';
export { clientIp, maskIp, parseTrustProxy } from './ip';
export type {
  AuthUser,
  CounterStore,
  CounterWindow,
  SessionStore,
  StoredSession,
  StoredToken,
  TokenStore,
  UserStore,
  WithPasswordHash,
} from './stores';
export { NO_SUCH_USER_ID } from './stores';
export { createDeviceToken, verifyDeviceToken } from './device';
export type { AuthMailEvent, Mailer } from './mail';
export type { AuditSink, AuthEvent, AuthEventType } from './audit';
export {
  SessionManager,
  type AttributeSchema,
  type MintInput,
  type MintResult,
  type SessionOptions,
  type SessionRefusal,
  type ValidateResult,
} from './session';
export { OneTimeTokens, type TokenRedemption } from './tokens';
export {
  accountKey,
  Throttle,
  type Hit,
  type LockoutOptions,
  type LoginGate,
  type RateLimitRule,
} from './throttle';
export type { AuthConfig, AuthPlugin, Door, PasswordResetJob } from './config';
export { DEFAULT_DOOR_LIMITS } from './config';
export { createAuth, definePlugin, type Auth, type PluginFlows } from './create-auth';
export {
  refuse,
  type AuthHooks,
  type HookInput,
  type HookResult,
  type IssueVia,
  type Refusal,
  type RevocationReason,
} from './hooks';
export type { IssuedSession, IssueOptions, PluginContext } from './plugin-context';
export type { LoginInput, LoginOutcome } from './flows/login';
export type { RegisterInput, RegisterOutcome } from './flows/register';
export type { VerifiedEmail } from './flows/email-verification';
export type { SessionSummary } from './flows/account';
