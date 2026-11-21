import type { AuthConfig, AuthUser } from '@noctcore/auth';

type AppConfig = AuthConfig<AuthUser, unknown, []>;
type EmailVerificationOptions = NonNullable<AppConfig['emailVerification']>;

// The defaults, written out. Pass them as `emailVerification` to createAuth,
// or leave the option out for the same values.
export const emailVerification = {
  // Typed by the signed-in user, bound to the account and the address.
  kind: 'code',
  ttl: '15m',
  digits: 8,
  maxAttempts: 5,
  // Link mode only: accept a link opened with no session.
  linkWithoutSession: false,
} satisfies EmailVerificationOptions;
