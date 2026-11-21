import type { LockoutOptions } from '@noctcore/auth';

// The defaults, written out. Pass them to createAuth as
// `throttle: { lockout }`, or leave the option out for the same values.
export const lockout = {
  // One account from one IP, then from every IP together.
  perAccountIp: { limit: 5, window: '15m' },
  perAccount: { limit: 10, window: '15m' },
  // Each new lock is three times the last, capped; a quiet day resets it.
  baseLock: '5m',
  maxLock: '1h',
  quietPeriod: '24h',
  // The owner's device cookies under a lock: each cookie's budget,
  // and the budget all of them share.
  perDevice: { limit: 5, window: '15m' },
  deviceMaxAge: '30d',
  // Off by default: a lock that never lapses, and an answer that
  // says "locked".
  // permanent: { afterLocks: 3 },
  revealLocked: false,
} satisfies LockoutOptions;
