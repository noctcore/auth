/**
 * What a new password must satisfy: a minimum and a maximum length, and
 * nothing else. Composition rules ("one digit, one symbol") push people toward
 * predictable patterns and are dropped, as NIST SP 800-63B recommends; the
 * breached-password check does the job they were meant to do.
 *
 * Length is counted in Unicode code points of the NFC form, so a password typed
 * on a phone (often NFD) and on a desktop is the same length and the same hash.
 *
 * Guide: Learn, "Passwords".
 */
export interface PasswordPolicy {
  readonly minLength: number;
  /** Bounds the hashing cost an attacker can make one request spend. */
  readonly maxLength: number;
}

export const DEFAULT_PASSWORD_POLICY: PasswordPolicy = { minLength: 12, maxLength: 256 };

export type PasswordPolicyVerdict = 'ok' | 'too_short' | 'too_long';

export function normalizePassword(password: string): string {
  return password.normalize('NFC');
}

export function checkPasswordPolicy(
  password: string,
  policy: PasswordPolicy = DEFAULT_PASSWORD_POLICY,
): PasswordPolicyVerdict {
  const length = [...normalizePassword(password)].length;

  if (length < policy.minLength) return 'too_short';
  if (length > policy.maxLength) return 'too_long';

  return 'ok';
}
