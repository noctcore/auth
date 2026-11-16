/**
 * Unguessable values. Every bearer secret (session tokens, email links, reset
 * tickets) is 32 bytes from the platform CSPRNG: 256 bits, far beyond what an
 * online or offline guesser can search. `Math.random` is never used.
 *
 * Guide: Learn, "Sessions and expiry".
 */
import { encodeHexLowerCase } from '@oslojs/encoding';

/** Fills the array with cryptographically secure random bytes. */
export type RandomSource = (bytes: Uint8Array) => void;

export const cryptoRandom: RandomSource = (bytes) => {
  globalThis.crypto.getRandomValues(bytes);
};

/** Bytes of entropy in every bearer secret the package mints. */
export const TOKEN_BYTES = 32;

const TOKEN_PATTERN = new RegExp(`^[0-9a-f]{${TOKEN_BYTES * 2}}$`, 'u');

export function randomBytes(length: number, random: RandomSource = cryptoRandom): Uint8Array {
  const bytes = new Uint8Array(length);

  random(bytes);

  return bytes;
}

/** A bearer secret: `TOKEN_BYTES` random bytes as lowercase hex (64 characters). */
export function generateToken(random: RandomSource = cryptoRandom): string {
  return encodeHexLowerCase(randomBytes(TOKEN_BYTES, random));
}

/**
 * Whether a caller-supplied string could be a token from `generateToken`.
 * A cheap pre-filter, not an authorisation check: it keeps junk (`*`, a
 * newline, a 4 kB blob) out of store keys so the store lookup that follows is
 * the only thing that can grant anything.
 */
export function isTokenShape(value: unknown): value is string {
  return typeof value === 'string' && TOKEN_PATTERN.test(value);
}

/**
 * A uniformly distributed numeric code of `digits` digits (6 to 9), for codes
 * a person types. Rejection sampling: taking a random 32-bit number modulo
 * 10^digits would make low codes slightly more likely.
 */
export function generateNumericCode(digits: number, random: RandomSource = cryptoRandom): string {
  if (!Number.isInteger(digits) || digits < 6 || digits > 9) {
    throw new RangeError('A numeric code has 6 to 9 digits');
  }

  const modulus = 10 ** digits;
  const limit = Math.floor(0x1_0000_0000 / modulus) * modulus;
  const buffer = new Uint8Array(4);

  for (;;) {
    random(buffer);
    const value = new DataView(buffer.buffer).getUint32(0);

    if (value < limit) return String(value % modulus).padStart(digits, '0');
  }
}
