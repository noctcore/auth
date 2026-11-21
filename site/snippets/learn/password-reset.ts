import type { AuthConfig, AuthUser } from '@noctcore/auth';

type AppConfig = AuthConfig<AuthUser, unknown, []>;
type PasswordResetOptions = NonNullable<AppConfig['passwordReset']>;

// The defaults, written out. Pass them as `passwordReset` to createAuth, or
// leave the option out for the same values.
export const passwordReset = {
  // A link: 32 random bytes, stored only as its SHA-256.
  kind: 'link',
  ttl: '1h',
  // With kind: 'code', the mail carries digits instead (ttl then defaults
  // to 15m), and a correct code becomes a ticket that sets the password.
  digits: 8,
  maxAttempts: 5,
  ticketTtl: '10m',
  // A completed reset proves the mailbox.
  markEmailVerified: true,
} satisfies PasswordResetOptions;
