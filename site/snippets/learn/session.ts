import type { SessionOptions } from '@noctcore/auth';

// The defaults, written out. Pass them as `session` to createAuth, or leave the
// option out and get the same values.
export const session = {
  // The store's TTL on the record: activity never extends it.
  absoluteTtl: '24h',
  rememberMeTtl: '30d',
  // Ends a session nobody has used for this long.
  idleTimeout: ({ rememberMe }) => (rememberMe ? '7d' : '30m'),
  // last-active is written at most this often, and never past the TTL.
  touchInterval: '60s',
  // One more sign-in evicts the oldest session.
  maxPerUser: 10,
} satisfies SessionOptions<unknown>;
