/**
 * Hashing secrets for storage and comparing them without leaking timing.
 *
 * A 32-byte random token needs no slow hash: nobody can brute-force 256 bits,
 * so SHA-256 is enough to make a leaked store useless for replay. A short code
 * (6 to 9 digits) is different: its whole space can be hashed in milliseconds,
 * so codes are stored as an HMAC under a server secret instead.
 *
 * Comparisons run on Node's `crypto.timingSafeEqual` where the runtime has it,
 * and on a JavaScript loop everywhere else.
 *
 * Guide: Learn, "Sessions and expiry".
 */
import { hmac } from '@oslojs/crypto/hmac';
import { SHA256, sha256 } from '@oslojs/crypto/sha2';
import { constantTimeEqual } from '@oslojs/crypto/subtle';
import { decodeHex, encodeBase64urlNoPadding, encodeHexLowerCase } from '@oslojs/encoding';

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

/** HMAC-SHA-256 of `message` under `key`, as unpadded base64url (43 characters). */
export function hmacSha256Base64url(key: Uint8Array, message: string): string {
  return encodeBase64urlNoPadding(hmac(SHA256, key, encoder.encode(message)));
}

/** Compares two byte arrays of the same length in constant time. */
export type BytesEqual = (a: Uint8Array, b: Uint8Array) => boolean;

type BuiltinHost = {
  readonly process?: { readonly getBuiltinModule?: (id: string) => unknown };
};

/**
 * Node's `crypto.timingSafeEqual` when the runtime has it, otherwise undefined.
 *
 * It is found through `process.getBuiltinModule` instead of an import, so a
 * bundler for an edge or browser runtime never sees `node:crypto`, and a
 * runtime without `process`, without `getBuiltinModule` (Node before 22.3) or
 * without the function gets undefined instead of a throw. Bun and Deno answer
 * like Node.
 */
export function findNativeTimingSafeEqual(host: unknown = globalThis): BytesEqual | undefined {
  try {
    const crypto = (host as BuiltinHost).process?.getBuiltinModule?.('node:crypto') as
      { readonly timingSafeEqual?: unknown } | undefined;

    const native = crypto?.timingSafeEqual;

    return typeof native === 'function' ? (native as BytesEqual) : undefined;
  } catch {
    return undefined;
  }
}

/**
 * A constant-time byte comparison over `native` when given, otherwise over a
 * JavaScript loop. Arrays of different lengths are unequal straight away: only
 * whether the lengths match is learned from the time, as before, and
 * `timingSafeEqual` (which throws on a length mismatch) only ever sees equal
 * lengths. Every caller here compares fixed-length digests, so the length is
 * no secret.
 */
export function bytesEqualWith(native: BytesEqual | undefined): BytesEqual {
  const compare = native ?? constantTimeEqual;

  return (a, b) => a.byteLength === b.byteLength && compare(a, b);
}

const bytesEqual = bytesEqualWith(findNativeTimingSafeEqual());

/**
 * Whether two lowercase hex digests are equal, in constant time. Anything that
 * is not well-formed hex is simply unequal (a lenient decoder could map two
 * different malformed strings to the same bytes).
 */
export function hexDigestsEqual(a: string, b: string): boolean {
  if (!HEX.test(a) || !HEX.test(b)) return false;

  return bytesEqual(decodeHex(a), decodeHex(b));
}

/**
 * Whether two secrets of any length are equal, without leaking either length:
 * both are hashed to 32 bytes first, so the comparison always sees equal
 * lengths.
 */
export function secretsEqual(a: string, b: string): boolean {
  return bytesEqual(sha256(encoder.encode(a)), sha256(encoder.encode(b)));
}
