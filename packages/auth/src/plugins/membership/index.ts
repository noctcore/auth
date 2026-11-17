/**
 * @noctcore/auth/membership: the guards every multi-user app needs around
 * roles and usually gets wrong. Nobody acts on themselves, the last admin of a
 * scope can be neither demoted nor removed (decided atomically by the store, so
 * two admins demoting each other at once cannot leave none), and a role change
 * or a removal revokes the member's sessions through the epoch fence.
 *
 * It is a plugin: flows under `auth.membership`, never HTTP endpoints. It does
 * not scope data: filtering every query by tenant stays in the app.
 *
 * ```ts
 * const auth = createAuth({ ...config, plugins: [membership({ store, adminRoles: ['owner'] })] });
 * const result = await auth.membership.changeRole({ session, scope: orgId, userId, role: 'member', meta });
 * if (!result.ok && result.code === 'last_admin') {
 *   // tell the admin to promote someone else first
 * }
 * ```
 *
 * Guide: Build, "Membership guards".
 */
import {
  addMember,
  changeRole,
  removeMember,
  type AddMemberInput,
  type ChangeRoleInput,
  type Context,
  type RemoveMemberInput,
} from './guards';
import { resolveSettings, type MembershipOptions } from './options';
import { definePlugin } from '../../core/plugins';
import { AuthConfigError } from '../../shared/errors';

export { MEMBERSHIP_REVOCATION } from './guards';
export type {
  AddMemberInput,
  ChangeRoleInput,
  MemberActionInput,
  RemoveMemberInput,
} from './guards';
export type { ManageContext, MemberAction, MembershipOptions } from './options';
export type { MembershipStore, MemberWrite, StoredMember } from '../../ports/membership';

/**
 * The membership plugin. `A` is the app's session attribute type, so the
 * sessions the flows take are typed like the core's.
 */
export function membership<A = Record<string, never>>(options: MembershipOptions) {
  const settings = resolveSettings(options);
  let bound = false;

  return definePlugin({
    id: 'membership',
    flows: (context) => {
      if (bound) throw new AuthConfigError('membership: one plugin instance per createAuth');

      bound = true;

      const r = { core: context as Context, store: options.store, settings };

      return {
        /** Adds a user to a scope with a role. */
        add: (input: AddMemberInput<A>) => addMember(r, input),
        /** Gives a member another role and revokes the member's sessions. */
        changeRole: (input: ChangeRoleInput<A>) => changeRole(r, input),
        /** Removes a member from a scope and revokes the member's sessions. */
        remove: (input: RemoveMemberInput<A>) => removeMember(r, input),
      };
    },
  });
}
