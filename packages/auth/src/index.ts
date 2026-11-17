/**
 * @noctcore/auth: the framework-free core.
 *
 * Primitives in this entry point: randomness, hashing, email normalisation,
 * password policy, the hasher contract and the breached-password check,
 * cookies, CSRF, captcha, client IP resolution, durations, results and errors.
 * Argon2id lives in `@noctcore/auth/argon2` so its native dependency stays
 * optional.
 */
export { systemClock, type Clock } from './ports/clock';
export { toMilliseconds, toSeconds, type Duration } from './shared/duration';
export { noopMetrics, silentLogger, type Logger, type Metrics } from './ports/logger';
export type { RequestMeta } from './shared/meta';
export {
  cryptoRandom,
  generateNumericCode,
  generateToken,
  isTokenShape,
  randomBytes,
  TOKEN_BYTES,
  type RandomSource,
} from './crypto/random';
export { hexDigestsEqual, hmacSha256Hex, secretsEqual, sha256Hex } from './crypto/hash';
export { normalizeEmail, type NormalizedEmail } from './shared/email';
export {
  AuthConfigError,
  fail,
  ok,
  toPublicError,
  type AuthErrorCode,
  type AuthFailure,
  type AuthResult,
  type AuthSuccess,
} from './shared/errors';
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
} from './http/cookie';
export {
  createCsrfToken,
  verifyCsrfToken,
  verifyFetchSite,
  verifyRequestOrigin,
} from './http/csrf';
export type { CaptchaDoor, CaptchaVerdict, CaptchaVerifier } from './ports/captcha';
export { turnstile, type TurnstileOptions } from './http/turnstile';
export { clientIp, maskIp, parseTrustProxy } from './http/ip';
export type {
  AuthUser,
  CounterStore,
  CounterWindow,
  EmailChangeResult,
  SessionStore,
  StoredSession,
  StoredToken,
  TokenStore,
  UserStore,
  WithPasswordHash,
} from './ports/stores';
export { NO_SUCH_USER_ID } from './ports/stores';
export { createDeviceToken, verifyDeviceToken } from './throttle/device-token';
export type { AuthMailEvent, Mailer } from './ports/mail';
export type { AuditSink, AuthEvent, AuthEventType } from './ports/audit';
export type {
  SecretCipher,
  StoredStepUp,
  StoredTotpFactor,
  StoredTrustedDevice,
  TwoFactorStore,
} from './ports/two-factor';
export type { MembershipStore, MemberWrite, StoredMember } from './ports/membership';
export type { InvitationStore, StoredInvitation } from './ports/invitations';
export { SessionManager } from './session/session-manager';
export type {
  AttributeSchema,
  MintInput,
  MintResult,
  SessionOptions,
  SessionRefusal,
  ValidateResult,
} from './session/session-types';
export { OneTimeTokens, type TokenRedemption } from './tokens/one-time-tokens';
export { Throttle } from './throttle/throttle';
export { accountKey } from './throttle/counter-keys';
export type { FactorGate, Hit, LockoutOptions, LoginGate, RateLimitRule } from './throttle/rules';
export type { AuthConfig, AuthPlugin, Door, PasswordResetJob } from './core/config';
export { DEFAULT_DOOR_LIMITS } from './core/config';
export { BACKGROUND_METRIC, type BackgroundOptions } from './core/background';
export { createAuth, type Auth } from './create-auth';
export { definePlugin, type PluginFlows } from './core/plugins';
export {
  refuse,
  type AuthHooks,
  type HookInput,
  type HookResult,
  type IssueVia,
  type Refusal,
  type RevocationReason,
} from './core/hooks';
export type { IssuedSession, IssueOptions, PluginContext } from './core/plugin-context';
export type { LoginInput, LoginOutcome } from './flows/login';
export type { RegisterInput, RegisterOutcome } from './flows/register';
export type { VerifiedEmail } from './flows/email-verification';
export type {
  ChangedEmail,
  EmailChangeRequested,
  RequestEmailChangeInput,
} from './flows/email-change';
export type { SessionSummary } from './flows/session-management';
