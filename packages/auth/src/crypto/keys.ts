/**
 * The server secret and the keys derived from it. One secret, a separate key
 * per use: an HMAC made for a one-time code can never double as a device token.
 *
 * During a rotation the previous secrets stay configured beside the current
 * one, so a value made under one of them still verifies. Every key is
 * derived from each secret, current first: signing, keyed hashing for
 * storage and new cookies use only the current key, and verification tries
 * each key in turn.
 */
import { encodeHexLowerCase } from '@oslojs/encoding';
import { hmacSha256Hex, secretsEqual } from './hash';
import { AuthConfigError } from '../shared/errors';

const MIN_SECRET_BYTES = 32;

/** A secret as configured: bytes, or a string taken as its UTF-8 bytes. */
export type SecretInput = Uint8Array | string;

function toBytes(secret: SecretInput): Uint8Array {
  return typeof secret === 'string' ? new TextEncoder().encode(secret) : secret;
}

/** The configured secret as bytes, refused when it is missing or too short to resist guessing. */
export function toSecret(secret: SecretInput | undefined): Uint8Array {
  if (secret === undefined) throw new AuthConfigError('secret is required (32 bytes or more)');

  const bytes = toBytes(secret);

  if (bytes.byteLength < MIN_SECRET_BYTES)
    throw new AuthConfigError(`secret must be at least ${MIN_SECRET_BYTES} bytes`);

  return bytes;
}

/**
 * The previous secrets of a rotation as bytes, oldest last. Each must be as
 * long as a secret, and none may equal the current secret or another
 * previous one: a repeat would only add work to every verification.
 */
export function toPreviousSecrets(
  previous: SecretInput | readonly SecretInput[] | undefined,
  current: Uint8Array,
): Uint8Array[] {
  if (previous === undefined) return [];

  const list: readonly unknown[] = Array.isArray(previous) ? previous : [previous];
  const seen = [encodeHexLowerCase(current)];

  return list.map((entry) => {
    if (typeof entry !== 'string' && !(entry instanceof Uint8Array))
      throw new AuthConfigError('previousSecret must be a string, bytes or a list of them');

    const bytes = toBytes(entry);

    if (bytes.byteLength < MIN_SECRET_BYTES)
      throw new AuthConfigError(`previousSecret must be at least ${MIN_SECRET_BYTES} bytes`);

    const hex = encodeHexLowerCase(bytes);

    if (seen.some((other) => secretsEqual(other, hex)))
      throw new AuthConfigError('previousSecret must differ from secret and from each other');

    seen.push(hex);

    return bytes;
  });
}

/** A key for one `purpose`, derived from the secret. */
export function deriveKey(secret: Uint8Array, purpose: string): Uint8Array {
  return new TextEncoder().encode(hmacSha256Hex(secret, `noctcore-auth:${purpose}`));
}

/** The key for `purpose` derived from each secret, current first. */
export function deriveKeys(
  secrets: readonly [Uint8Array, ...Uint8Array[]],
  purpose: string,
): [Uint8Array, ...Uint8Array[]] {
  const [current, ...previous] = secrets;

  return [deriveKey(current, purpose), ...previous.map((secret) => deriveKey(secret, purpose))];
}
