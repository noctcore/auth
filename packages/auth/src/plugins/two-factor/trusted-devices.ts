/**
 * "Remember this device": a device that passed the login challenge may skip it
 * on later logins, and nothing else.
 *
 * - The device token is 32 bytes from the CSPRNG; the store holds only its
 *   SHA-256, so a leaked table cannot be presented as a cookie.
 * - It is bound to the user and to their revocation epoch at the time it was
 *   trusted. A password change, a reset, "sign out everywhere" and turning the
 *   factor off all bump or clear that, so a token stolen before any of them is
 *   dead after it, even if the store's cleanup never ran.
 * - It expires (30 days by default) and each user keeps a few at most.
 * - It replaces the second factor at the challenge only: the password is
 *   still checked first, and a step-up for a sensitive action still needs a code.
 *
 * Guide: Learn, "Second factors".
 */
import type { Runtime } from './runtime';
import { sha256Hex } from '../../crypto/hash';
import { generateToken, isTokenShape } from '../../crypto/random';
import { longLivedCookie, type CookieSpec } from '../../http/cookie';
import { NO_SUCH_USER_ID } from '../../ports/stores';
import type { RequestMeta } from '../../shared/meta';

/** Base name of the trusted-device cookie; `__Host-` is prepended when the session cookie is secure. */
export const TRUSTED_DEVICE_COOKIE = 'two-factor-device';

/** A device just trusted: set `cookie` on the response. */
export interface TrustedDevice {
  readonly token: string;
  readonly expiresAt: number;
  readonly cookie: CookieSpec;
}

/** Trusts the device a challenge was just passed on, at the epoch of the session it got. */
export async function trustDevice(
  runtime: Runtime,
  userId: string,
  epoch: number,
  meta: RequestMeta,
): Promise<TrustedDevice | null> {
  const policy = runtime.settings.trustedDevices;

  if (!policy) return null;

  const { core } = runtime;
  const token = generateToken(core.random);
  const now = core.clock.now();
  const expiresAt = now + policy.ttlMs;

  await runtime.store.addTrustedDevice(
    { userId, hash: sha256Hex(token), epoch, createdAt: now, expiresAt },
    policy.maxPerUser,
  );

  await core.emit({ type: 'two_factor.trusted_device_added', userId }, meta);

  const maxAge = Math.floor(policy.ttlMs / 1000);

  return {
    token,
    expiresAt,
    cookie: longLivedCookie(core.cookie, TRUSTED_DEVICE_COOKIE, token, maxAge, meta.origin),
  };
}

/** Whether `token` names a live device of this user, trusted at `epoch`. */
export async function isTrustedDevice(
  runtime: Runtime,
  userId: string | null,
  token: unknown,
  epoch: number,
): Promise<boolean> {
  if (!runtime.settings.trustedDevices || !isTokenShape(token)) return false;

  // The store only finds a device under its own user; no user, no device.
  const device = await runtime.store.findTrustedDevice(userId ?? NO_SUCH_USER_ID, sha256Hex(token));

  return device !== null && device.epoch === epoch && device.expiresAt > runtime.core.clock.now();
}
