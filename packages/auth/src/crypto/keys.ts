/**
 * The server secret and the keys derived from it. One secret, a separate key
 * per use: an HMAC made for a one-time code can never double as a device token.
 */
import { hmacSha256Hex } from './hash';
import { AuthConfigError } from '../shared/errors';

const MIN_SECRET_BYTES = 32;

/** The configured secret as bytes, refused when it is missing or too short to resist guessing. */
export function toSecret(secret: Uint8Array | string | undefined): Uint8Array {
  if (secret === undefined) throw new AuthConfigError('secret is required (32 bytes or more)');

  const bytes = typeof secret === 'string' ? new TextEncoder().encode(secret) : secret;

  if (bytes.byteLength < MIN_SECRET_BYTES)
    throw new AuthConfigError(`secret must be at least ${MIN_SECRET_BYTES} bytes`);

  return bytes;
}

/** A key for one `purpose`, derived from the secret. */
export function deriveKey(secret: Uint8Array, purpose: string): Uint8Array {
  return new TextEncoder().encode(hmacSha256Hex(secret, `noctcore-auth:${purpose}`));
}
