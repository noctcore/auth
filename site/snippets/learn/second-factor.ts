import type { TwoFactorOptions } from '@noctcore/auth/two-factor';

// The plugin's limits and windows, written out. Pass them to twoFactor()
// beside store, cipher and issuer, or leave them out for the same values.
export const secondFactor = {
  // Wrong codes per account, from every IP together, before the factor
  // locks with the password lockout's capped backoff.
  attempts: { limit: 5, window: '15m' },
  // Code checks per client IP.
  perIp: { limit: 10, window: '1m' },
  // How long a code proved in this session counts for sensitive actions.
  stepUpWindow: '10m',
  // "Remember this device": skips the code after a correct password,
  // never the password and never a step-up. `false` turns it off.
  trustedDevices: { ttl: '30d', maxPerUser: 5 },
} satisfies Partial<TwoFactorOptions>;
