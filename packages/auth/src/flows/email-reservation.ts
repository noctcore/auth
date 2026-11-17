/**
 * Holding an address that an email change gave up, for the account that gave
 * it up, while that change's revert link lives. Without it, whoever made the
 * change could register the old address, and the revert would have nowhere to
 * go back to.
 *
 * The hold is a token of purpose `email-reserved` stored under a key derived
 * from the address (a SHA-256, so the token store never sees the address in
 * its user column) and no secret anyone is shown. It expires with the revert
 * link, and a revert releases it. Sign-up, other accounts' change requests and
 * confirms treat a held address as one that has an account, with the answers
 * they give for that.
 *
 * Guide: Learn, "Email change".
 */
import { PURPOSE } from './settings';
import type { AuthCore } from '../core/auth-core';
import { sha256Hex } from '../crypto/hash';
import type { AuthUser } from '../ports/stores';
import type { NormalizedEmail } from '../shared/email';

/** The token store "user" a hold is filed under. The prefix keeps it apart from real user ids. */
function holdKey(email: NormalizedEmail): string {
  return `email-reserved:${sha256Hex(email)}`;
}

/** Holds `email` for `userId` for `ttlMs`, replacing any earlier hold on it. */
export async function reserveAddress<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  email: NormalizedEmail,
  userId: string,
  ttlMs: number,
): Promise<void> {
  await core.tokens.issueLink(PURPOSE.emailReserved, holdKey(email), ttlMs, { userId });
}

/** The id of the account holding `email`, or null when nobody holds it. */
export async function addressHolder<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  email: NormalizedEmail,
): Promise<string | null> {
  const hold = await core.tokens.findLive(PURPOSE.emailReserved, holdKey(email));

  return hold?.data['userId'] ?? null;
}

export async function releaseAddress<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  email: NormalizedEmail,
): Promise<void> {
  await core.tokens.revokeAll(holdKey(email), [PURPOSE.emailReserved]);
}
