import type { PasswordPolicy } from '@noctcore/auth';
import type { Argon2idOptions } from '@noctcore/auth/argon2';

// The defaults, written out. Pass them to createAuth as
// `password: { hasher: argon2id(hashing), policy }`, or leave them out for
// the same values.
export const hashing = {
  // KiB of memory for each hash: OWASP's floor. Raise this on a box that
  // can afford it, not the passes or the lanes.
  memoryCost: 19_456,
  // Passes, the auth guide's floor, and lanes.
  timeCost: 3,
  parallelism: 1,
} satisfies Argon2idOptions;

// Counted in Unicode code points after NFC. No composition rules.
export const policy = { minLength: 12, maxLength: 256 } satisfies PasswordPolicy;
