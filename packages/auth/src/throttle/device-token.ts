/**
 * Trusted-device tokens for the lockout bypass. Every issued session (so only
 * after a full login, every factor included) hands the browser a cookie
 * holding `<id>.<issuedAt>.<epoch>.<hmac>`. The HMAC binds the random device
 * id to the user id, the user's revocation epoch and the issue time:
 *
 * - a password change, a reset and revoke-all all bump the epoch, so every
 *   device token issued before them stops working;
 * - a token older than the configured max age (30 days by default) is refused,
 *   whatever the cookie's own expiry says.
 *
 * A valid token never skips the password check and grants no session. It only
 * lets a correct password through an account lock (see throttle.ts).
 */
import { encodeHexLowerCase } from '@oslojs/encoding';
import { hexDigestsEqual, hmacSha256Hex } from '../crypto/hash';
import { cryptoRandom, randomBytes, type RandomSource } from '../crypto/random';

// Canonical decimals only (no leading zeros), so one token has one spelling.
const TOKEN = /^([0-9a-f]{32})\.(0|[1-9]\d{0,15})\.(0|[1-9]\d{0,15})\.([0-9a-f]{64})$/u;

export interface DeviceClaims {
  readonly userId: string;
  /** The user's revocation epoch when the token was issued. */
  readonly epoch: number;
  /** Issue time, ms since the epoch. */
  readonly issuedAt: number;
}

function mac(key: Uint8Array, id: string, claims: DeviceClaims): string {
  const { userId, epoch, issuedAt } = claims;

  return hmacSha256Hex(key, `device:${userId.length}:${userId}:${epoch}:${issuedAt}:${id}`);
}

/** A new device token for these claims. */
export function createDeviceToken(
  key: Uint8Array,
  claims: DeviceClaims,
  random: RandomSource = cryptoRandom,
): string {
  const id = encodeHexLowerCase(randomBytes(16, random));

  return `${id}.${claims.issuedAt}.${claims.epoch}.${mac(key, id, claims)}`;
}

export interface DeviceCheck {
  readonly userId: string;
  /** The user's current epoch. */
  readonly epoch: number;
  readonly now: number;
  readonly maxAgeMs: number;
}

/** The device id when the token is valid for this user, epoch and age, otherwise null. */
export function verifyDeviceToken(
  key: Uint8Array,
  token: unknown,
  check: DeviceCheck,
): string | null {
  if (typeof token !== 'string') return null;

  const match = TOKEN.exec(token);

  if (!match) return null;

  const [, id = '', issued = '', epoch = '', given = ''] = match;
  const issuedAt = Number(issued);

  if (Number(epoch) !== check.epoch) return null;
  // A minute of clock skew between servers, no more.
  if (issuedAt > check.now + 60_000 || check.now - issuedAt > check.maxAgeMs) return null;

  return hexDigestsEqual(
    given,
    mac(key, id, { userId: check.userId, epoch: check.epoch, issuedAt }),
  )
    ? id
    : null;
}
