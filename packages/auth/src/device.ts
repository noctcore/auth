/**
 * Trusted-device tokens for the lockout bypass. After a successful login the
 * flow hands the browser a long-lived cookie holding `<id>.<hmac>`, where the
 * HMAC binds the random device id to the account. A later login for the same
 * account that presents a valid token spends that device's own small budget
 * instead of being refused by the account lock (see throttle.ts).
 *
 * The token proves only that this browser once signed in to this account. It
 * grants no session and skips no password check.
 */
import { encodeHexLowerCase } from '@oslojs/encoding';
import { hexDigestsEqual, hmacSha256Hex } from './hash';
import { cryptoRandom, randomBytes, type RandomSource } from './random';

const ID = /^[0-9a-f]{32}$/u;

function mac(key: Uint8Array, account: string, id: string): string {
  return hmacSha256Hex(key, `device:${account.length}:${account}:${id}`);
}

/** A new device token for an account key (see `accountKey`). */
export function createDeviceToken(key: Uint8Array, account: string, random: RandomSource = cryptoRandom): string {
  const id = encodeHexLowerCase(randomBytes(16, random));
  return `${id}.${mac(key, account, id)}`;
}

/** The device id when the token is valid for this account, otherwise null. */
export function verifyDeviceToken(key: Uint8Array, account: string, token: unknown): string | null {
  if (typeof token !== 'string') return null;
  const dot = token.indexOf('.');
  const id = token.slice(0, dot);
  if (dot <= 0 || !ID.test(id)) return null;
  return hexDigestsEqual(token.slice(dot + 1), mac(key, account, id)) ? id : null;
}
