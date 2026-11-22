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
 * Sign-up, sign-up through an invitation, other accounts' change requests and
 * confirms treat a held address as one that has an account. Plugins ask the
 * plugin context's `isAddressHeld` (wired to `heldAccount` by `createAuth`);
 * paths of the app that create users (admin create, a first SSO login,
 * imports) must ask `auth.isAddressHeld`.
 *
 * Guide: Learn, "Email change"; Build, "Email change".
 */
import { PURPOSE } from './settings';
import type { AuthCore } from '../core/auth-core';
import type { AuthUser, UserStore } from '../ports/stores';
import type { NormalizedEmail } from '../shared/email';
import type { OneTimeTokens } from '../tokens/one-time-tokens';

/** What reading a hold needs: the flows' core and a plugin's context both have it. */
interface HoldReader {
  readonly tokens: OneTimeTokens;
  readonly users: Pick<UserStore<AuthUser>, 'findById' | 'changeEmail'>;
}

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
export async function addressHolder(
  core: Pick<HoldReader, 'tokens'>,
  email: NormalizedEmail,
): Promise<string | null> {
  const hold = await core.tokens.findKeyed(PURPOSE.emailReserved, holdKey(email));

  return hold?.userId ?? null;
}

/**
 * The account `email` is held for, when the hold still counts: the rule every
 * path that creates a user applies (sign-up, sign-up through an invitation,
 * `auth.isAddressHeld`). A holder that is gone can never revert, so its
 * address is free. Only a store that can change emails can have held
 * addresses, so other apps skip the lookup. Two reads at most: the hold, then
 * the holder.
 */
export async function heldAccount(
  core: HoldReader,
  email: NormalizedEmail,
): Promise<{ id: string; email: NormalizedEmail } | null> {
  if (typeof core.users.changeEmail !== 'function') return null;

  const holderId = await addressHolder(core, email);

  if (holderId === null) return null;

  const holder = await core.users.findById(holderId);

  return holder ? { id: holder.id, email } : null;
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
  const normalized = core.normalizeEmail(email);

  return normalized !== null && (await heldAccount(core, normalized)) !== null;
}
