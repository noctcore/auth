/**
 * Holding an address that an email change gave up, for the account that gave
 * it up, while that change's revert link lives. Without it, whoever made the
 * change could register the old address, and the revert would have nowhere to
 * go back to.
 *
 * The hold is a token of purpose `email-reserved`, filed under the holding
 * account's own user id (so a foreign key from the token table to the users
 * table holds) and found by a key derived from the address: the row stores
 * the SHA-256 of `email-reserved:<address>`, never the address, and no secret
 * anyone is shown. It expires with the revert link, and a revert releases it.
 * Sign-up, other accounts' change requests and confirms treat a held address
 * as one that has an account. Paths of the app that create users (invites,
 * admin create, a first SSO login, imports) must ask `auth.isAddressHeld`.
 *
 * Guide: Learn, "Email change"; Build, "Email change".
 */
import { PURPOSE } from './settings';
import type { AuthCore } from '../core/auth-core';
import type { AuthUser } from '../ports/stores';
import { normalizeEmail, type NormalizedEmail } from '../shared/email';

function holdKey(email: NormalizedEmail): string {
  return `email-reserved:${email}`;
}

/** Holds `email` for `userId` for `ttlMs`, replacing the account's earlier hold and any other hold on the address. */
export async function reserveAddress<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  email: NormalizedEmail,
  userId: string,
  ttlMs: number,
): Promise<void> {
  await core.tokens.putKeyed(PURPOSE.emailReserved, userId, holdKey(email), ttlMs);
}

/** The id of the account holding `email`, or null when nobody holds it. */
export async function addressHolder<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  email: NormalizedEmail,
): Promise<string | null> {
  const hold = await core.tokens.findKeyed(PURPOSE.emailReserved, holdKey(email));

  return hold?.userId ?? null;
}

/** Drops the account's hold, whichever address it is on. */
export async function releaseAddress<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  userId: string,
): Promise<void> {
  await core.tokens.revokeAll(userId, [PURPOSE.emailReserved]);
}

/**
 * Whether `email` is held for an account whose email change away from it can
 * still be reverted. Every path of the app that creates a user, or gives an
 * existing one this address, must refuse a held address the way it refuses a
 * taken one. An unreadable address is not held.
 */
export async function isAddressHeld<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  email: string,
): Promise<boolean> {
  const normalized = normalizeEmail(email);

  return normalized !== null && (await addressHolder(core, normalized)) !== null;
}
