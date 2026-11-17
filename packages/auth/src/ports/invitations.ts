/**
 * The contract the invitations plugin (`@noctcore/auth/invitations`) is
 * handed: pending invitations, each bound to one scope and one normalised
 * address, found by a keyed hash of its token and spent exactly once.
 *
 * Every write that must not happen twice is atomic, and the conformance suite
 * in `@noctcore/auth/testing` (`invitationStoreConformance`) checks it:
 *
 * - `consume` removes and returns an invitation in one step: of many
 *   concurrent callers exactly one gets it, so two clicks or two browsers
 *   cannot both accept;
 * - `create` refuses a second live invitation for the same scope and address,
 *   also under concurrency, so repeated invitations cannot flood a mailbox.
 *
 * Guide: Build, "Invitations".
 */

/** A pending invitation as stored. Never the token: only its keyed hash. */
export interface StoredInvitation {
  /** A random id, safe to show to admins and to pass to `revoke`. */
  readonly id: string;
  /** HMAC-SHA-256 of the token under a key derived for invitations. */
  readonly hash: string;
  /** The app's scope id: a tenant, organisation or team. */
  readonly scope: string;
  /** The invited address, normalised. */
  readonly email: string;
  readonly inviterId: string;
  /** What the app wants to remember about the invitation (a role, say). */
  readonly payload: Readonly<Record<string, string>>;
  /** ms since the epoch. */
  readonly createdAt: number;
  /** ms since the epoch. An invitation at or past it is never accepted. */
  readonly expiresAt: number;
}

export interface InvitationStore {
  /**
   * Stores the invitation unless a live one (expiring after `now`) exists for
   * the same scope and address: then false, and nothing written. An expired
   * one is replaced. Of many concurrent creates for one scope and address, at
   * most one gets true. The store may drop an invitation after `expiresAt`.
   */
  create(invitation: StoredInvitation, now: number): Promise<boolean>;
  /** The invitation with this hash (expired or not: the caller checks). */
  findByHash(hash: string): Promise<StoredInvitation | null>;
  /** Atomically removes and returns the invitation: of many concurrent callers exactly one gets it. */
  consume(hash: string): Promise<StoredInvitation | null>;
  /** The scope's invitations that expire after `now`, in no particular order. */
  listByScope(scope: string, now: number): Promise<StoredInvitation[]>;
  /** Deletes the invitation with this id if it belongs to `scope`; whether it did. */
  revoke(scope: string, id: string): Promise<boolean>;
  /** Deletes every invitation `inviterId` sent. */
  deleteByInviter(inviterId: string): Promise<void>;
}
