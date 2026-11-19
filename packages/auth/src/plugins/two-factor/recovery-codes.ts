/**
 * Recovery codes: the way back in when the phone is gone, and so the weakest
 * part of any second factor. They are treated like passwords that can be used
 * once:
 *
 * - 10 codes of 10 characters from a 32-symbol alphabet (Crockford base32, no
 *   I, L, O or U to misread): 50 bits each, from the CSPRNG.
 * - Shown once. Only an HMAC under a key derived from the server secret,
 *   bound to the user, is stored, so a leaked table cannot be searched offline
 *   and a row copied onto another account matches nothing.
 * - Spent by an atomic delete in the store, so one code never signs in twice.
 * - Regenerating replaces the whole set in one write: every old code dies.
 * - Codes imported from an app's earlier scheme are stored under a prefix of
 *   their own, so the plugin can tell them from its own and never matches one
 *   by its own hash. Spending one at login moves the user onto a new set.
 *
 * Guide: Learn, "Second factors".
 */
import { randomBytes, type RandomSource } from '../../crypto/random';
import { AuthConfigError } from '../../shared/errors';

export const RECOVERY_CODE_COUNT = 10;
const RECOVERY_CODE_LENGTH = 10;
const ALPHABET = '0123456789abcdefghjkmnpqrstvwxyz';

/** The keyedHash purpose: a recovery code HMAC can never double as another plugin's. */
export const RECOVERY_CODE_PURPOSE = 'two-factor-recovery-code';

const NOT_ALPHANUMERIC = /[^0-9A-Za-z]/u;
const SHAPE = /^[0-9a-hjkmnp-tv-z]{10}$/u;
const SEPARATORS = /[\s-]/gu;
/** Longest input looked at: a code with generous spacing, nothing like a 4 kB blob. */
const MAX_INPUT = 32;

/** One code, shown as `xxxxx-xxxxx`. 32 symbols divide 256, so masking a byte is uniform. */
export function generateRecoveryCode(random: RandomSource): string {
  const chars = Array.from(randomBytes(RECOVERY_CODE_LENGTH, random), (b) => ALPHABET[b & 31]);

  return `${chars.slice(0, 5).join('')}-${chars.slice(5).join('')}`;
}

export function generateRecoveryCodes(random: RandomSource): string[] {
  return Array.from({ length: RECOVERY_CODE_COUNT }, () => generateRecoveryCode(random));
}

/**
 * The code as stored: separators and spaces dropped, lower case. Null when it
 * cannot be a recovery code. Only ASCII is lowered, so no Unicode case folding
 * can turn another string into a valid code.
 */
export function normalizeRecoveryCode(input: unknown): string | null {
  if (typeof input !== 'string' || input.length > MAX_INPUT) return null;

  const compact = input.replace(SEPARATORS, '');

  if (NOT_ALPHANUMERIC.test(compact)) return null;

  const lower = compact.toLowerCase();

  return SHAPE.test(lower) ? lower : null;
}

/** The prefix of an imported code's hash in the store: no hash the plugin computes starts with it. */
export const IMPORTED_RECOVERY_CODE_PREFIX = 'imported:';

/** Longest input handed to the app's `importedRecoveryCodes.hash`. */
const MAX_IMPORTED_INPUT = 64;

/**
 * The stored form of recovery code hashes carried over from an app's earlier
 * scheme: pass the result to the store's `replaceRecoveryCodes(userId, ...)`
 * from the migration script. Only the plugin's `importedRecoveryCodes.hash`
 * option checks them; without it they match nothing.
 */
export function importedRecoveryCodeHashes(hashes: readonly string[]): string[] {
  return hashes.map((hash) => {
    if (typeof hash !== 'string' || hash.length === 0)
      throw new AuthConfigError(
        'twoFactor: an imported recovery code hash must be a non-empty string',
      );

    return `${IMPORTED_RECOVERY_CODE_PREFIX}${hash}`;
  });
}

/** The typed input as the app's hash sees it, or null when it cannot be a code: not a string, or longer than any code. */
export function importedRecoveryCodeInput(input: unknown): string | null {
  return typeof input === 'string' && input.length > 0 && input.length <= MAX_IMPORTED_INPUT
    ? input
    : null;
}
