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
export { pwnedPasswords, type BreachChecker, type BreachVerdict, type PwnedPasswordsOptions } from './password/breach';
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
export { createCsrfToken, verifyCsrfToken, verifyRequestOrigin } from './csrf';
export {
  turnstile,
  type CaptchaDoor,
  type CaptchaVerdict,
  type CaptchaVerifier,
  type TurnstileOptions,
} from './captcha';
export { clientIp, maskIp, parseTrustProxy } from './ip';
