/**
 * The contract the membership plugin (`@noctcore/auth/membership`) is handed:
 * who belongs to which scope (a tenant, an organisation, a team: the app
 * decides what a scope is) and with which role. Roles are the app's own
 * strings; the plugin only needs to know which of them are admin roles.
 *
 * The store decides the race, not the plugin: a role change or a removal that
 * would leave a scope without an admin is refused inside the same atomic step
 * that would write it, so two admins demoting each other at the same moment
 * cannot both succeed. The conformance suite in `@noctcore/auth/testing`
 * (`membershipStoreConformance`) checks it under concurrency.
 *
 * Data scoping (filtering every query by the scope) stays in the app: this
 * store only answers who is a member and with which role.
 *
 * Guide: Build, "Membership guards".
 */

/** One user's membership of one scope. */
export interface StoredMember {
  /** The app's scope id: a tenant, organisation or team. */
  readonly scope: string;
  readonly userId: string;
  /** The app's role name. */
  readonly role: string;
}

/**
 * The outcome of a guarded write.
 *
 * - `done`: written.
 * - `missing`: the user is not a member of the scope.
 * - `stale`: the member's role is no longer the `from` the caller decided on.
 * - `last_admin`: the write would leave the scope without a member holding an admin role.
 */
export type MemberWrite = 'done' | 'missing' | 'stale' | 'last_admin';

export interface MembershipStore {
  findMember(scope: string, userId: string): Promise<StoredMember | null>;
  /** Every member of the scope, in no particular order. */
  listMembers(scope: string): Promise<StoredMember[]>;
  /** Adds the member. False (and nothing written) when the user is already a member of the scope. */
  addMember(member: StoredMember): Promise<boolean>;
  /**
   * One atomic step: sets the role to `to` only if the member still holds
   * `from`, and, when `from` is in `adminRoles` and `to` is not, only if
   * another member of the scope holds a role in `adminRoles`. Of two
   * concurrent demotions of the last two admins, at most one is `done`.
   */
  changeRole(input: {
    readonly scope: string;
    readonly userId: string;
    readonly from: string;
    readonly to: string;
    readonly adminRoles: readonly string[];
  }): Promise<MemberWrite>;
  /**
   * One atomic step: removes the member only if it still holds `from`, and,
   * when `from` is in `adminRoles`, only if another member of the scope holds
   * a role in `adminRoles`.
   */
  removeMember(input: {
    readonly scope: string;
    readonly userId: string;
    readonly from: string;
    readonly adminRoles: readonly string[];
  }): Promise<MemberWrite>;
}
