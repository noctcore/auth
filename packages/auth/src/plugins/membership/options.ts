/**
 * The membership plugin's options, checked once when the plugin is created.
 */
import type { MembershipStore, StoredMember } from '../../ports/membership';
import { AuthConfigError } from '../../shared/errors';

/** What an admin action does. */
export type MemberAction = 'add' | 'change-role' | 'remove';

/** What `canManage` is asked. Every member here was read from the store, never from the session. */
export interface ManageContext {
  /** The acting user's membership of the scope. */
  readonly actor: StoredMember;
  readonly action: MemberAction;
  /** The member acted on. */
  readonly userId: string;
  /** The target's role now; undefined when adding. */
  readonly from: string | undefined;
  /** The role being given; undefined when removing. */
  readonly to: string | undefined;
}

export interface MembershipOptions {
  /** Who belongs to which scope. `@noctcore/auth-prisma` and `@noctcore/auth-redis` ship one. */
  readonly store: MembershipStore;
  /**
   * The roles that count as admin. The last member holding one of them in a
   * scope can be neither demoted to another role nor removed. At least one.
   */
  readonly adminRoles: readonly string[];
  /**
   * Whether the actor may perform this action. Default: the actor holds an
   * admin role in the scope. The actor is read from the store on every call,
   * so a demoted admin loses the right at once. Throwing refuses.
   */
  readonly canManage?: (context: ManageContext) => boolean | Promise<boolean>;
  /**
   * Revoke every session of a member on an attempted change to another role,
   * or a removal, before and after the write: an attempt the store refuses
   * (`last_admin`, a stale or missing target) has still revoked. Default false: the guards read roles from the store on every call, so
   * they never need it. Turn it on when the app copies roles into session
   * attributes or caches them per session. The epoch is per user, so the
   * member is signed out everywhere, in every scope, and with the two-factor
   * plugin their trusted devices are voided: an admin of any scope the member
   * belongs to can sign them out.
   */
  readonly revokeSessionsOnChange?: boolean;
}

export interface MembershipSettings {
  readonly adminRoles: readonly string[];
  readonly canManage: (context: ManageContext) => boolean | Promise<boolean>;
  readonly revokeSessionsOnChange: boolean;
}

export function resolveSettings(options: MembershipOptions): MembershipSettings {
  if (!options.store) throw new AuthConfigError('membership: store is required');

  const adminRoles = options.adminRoles;

  if (
    !Array.isArray(adminRoles) ||
    adminRoles.length === 0 ||
    !adminRoles.every((role) => typeof role === 'string' && role.length > 0)
  )
    throw new AuthConfigError('membership: adminRoles must list at least one role');

  const admins = new Set(adminRoles);

  return {
    adminRoles: [...admins],
    canManage: options.canManage ?? (({ actor }) => admins.has(actor.role)),
    revokeSessionsOnChange: options.revokeSessionsOnChange === true,
  };
}
