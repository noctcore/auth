import type { AuthConfig, AuthUser, Duration } from '@noctcore/auth';

type Config = AuthConfig<AuthUser, unknown, []>;

// The defaults, written out. Pass them as `emailChange` to createAuth, or
// leave the option out for the same values.
export const emailChange = {
  // A code typed in a signed-in session of the same account.
  kind: 'code',
  ttl: '15m',
  digits: 8,
  // Wrong guesses, each counted before the comparison.
  maxAttempts: 5,
  // The revert link mailed to the old address: never shorter than this.
  revertTtl: '7d',
  // After a revert, the address the account lost stays off limits.
  blockAfterRevert: '30d',
} satisfies NonNullable<Config['emailChange']>;

// Under `session`: how recent the password proof must be to ask for a change.
export const freshAuthAge: Duration = '10m';
