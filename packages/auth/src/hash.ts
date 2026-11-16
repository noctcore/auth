/**
 * Hashing secrets for storage and comparing them without leaking timing.
 *
 * A 32-byte random token needs no slow hash: nobody can brute-force 256 bits,
 * so SHA-256 is enough to make a leaked store useless for replay. A short code
 * (6 to 9 digits) is different: its whole space can be hashed in milliseconds,
 * so codes are stored as an HMAC under a server secret instead.
 *
 * Guide: Learn, "Why tokens are hashed".
 */
import { hmac } from '@oslojs/crypto/hmac';
import { SHA256, sha256 } from '@oslojs/crypto/sha2';
import { constantTimeEqual } from '@oslojs/crypto/subtle';
import { decodeHex, encodeHexLowerCase } from '@oslojs/encoding';

const encoder = new TextEncoder();
const HEX = /^(?:[0-9a-f]{2})+$/u;

/** SHA-256 of the UTF-8 string, as lowercase hex. The store key of every token. */
export function sha256Hex(value: string): string {
  return encodeHexLowerCase(sha256(encoder.encode(value)));
}

/** HMAC-SHA-256 of `message` under `key`, as lowercase hex. */
export function hmacSha256Hex(key: Uint8Array, message: string): string {
  return encodeHexLowerCase(hmac(SHA256, key, encoder.encode(message)));
}

/**
 * Whether two lowercase hex digests are equal, in constant time. Anything that
 * is not well-formed hex is simply unequal (a lenient decoder could map two
 * different malformed strings to the same bytes).
 */
export function hexDigestsEqual(a: string, b: string): boolean {
  if (!HEX.test(a) || !HEX.test(b)) return false;

  return constantTimeEqual(decodeHex(a), decodeHex(b));
}

/**
 * Whether two secrets of any length are equal, without leaking either length:
 * both are hashed to 32 bytes first, so the comparison always sees equal
 * lengths.
 */
export function secretsEqual(a: string, b: string): boolean {
  return constantTimeEqual(sha256(encoder.encode(a)), sha256(encoder.encode(b)));
}
