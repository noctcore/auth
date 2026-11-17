/**
 * The membership guards and flows: add a member, change a member's role, remove a member.
 *
 * Each flow runs the same checks in the same order, and each refusal is a
 * typed failure with a code, never an exception that carries membership data:
 *
 * 1. Acting on yourself is refused (`self_target`), comparing user ids.
 * 2. The actor's own membership is read from the store, never from the
 *    session, and `canManage` decides on it (`forbidden`). A lookup that throws
 *    or finds nothing refuses: the guards fail closed.
 * 3. The write is one atomic, guarded step in the store: it refuses to leave
 *    the scope without an admin (`last_admin`) and to apply a decision made on
 *    a role that changed meanwhile.
 * 4. After a role change or a removal, every session of the member is revoked
 *    through the epoch fence. The write comes first: a login that read the old
 *    epoch is refused by the fence, and one that starts after the bump reads
 *    the new role.
 */
import type { MemberAction, MembershipSettings } from './options';
import type { PluginContext } from '../../core/plugin-context';
import type { MembershipStore, MemberWrite, StoredMember } from '../../ports/membership';
import type { AuthUser, StoredSession } from '../../ports/stores';
import { describeError } from '../../shared/describe-error';
import {
  fail,
  ok,
  type AuthErrorCode,
  type AuthFailure,
  type AuthResult,
} from '../../shared/errors';
import type { RequestMeta } from '../../shared/meta';

// The plugin is written against any app's user and attribute types.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Context = PluginContext<AuthUser, any>;

export interface Runtime {
  readonly core: Context;
  readonly store: MembershipStore;
  readonly settings: MembershipSettings;
}

/** The revocation reason the hooks see when a role change or a removal ends sessions. */
export const MEMBERSHIP_REVOCATION = 'membership-changed';

/** What every membership flow takes: the acting session, the scope and the member acted on. */
export interface MemberActionInput<A> {
  readonly session: StoredSession<A>;
  readonly scope: string;
  readonly userId: string;
  readonly meta: RequestMeta;
}

export interface AddMemberInput<A> extends MemberActionInput<A> {
  readonly role: string;
}

export interface ChangeRoleInput<A> extends MemberActionInput<A> {
  readonly role: string;
}

export type RemoveMemberInput<A> = MemberActionInput<A>;

/** Adds a user to a scope. No session is revoked: nothing was taken away. */
export async function addMember<A>(
  r: Runtime,
  input: AddMemberInput<A>,
): Promise<AuthResult<StoredMember>> {
  const allowed = await authorize(r, 'add', input, input.role);

  if (!allowed.ok) return allowed;

  const member: StoredMember = { scope: input.scope, userId: input.userId, role: input.role };

  if (!(await r.store.addMember(member)))
    return refused(r, input, 'forbidden', 'already_member', 'add');

  await r.core.emit(event('membership.added', input, { to: input.role }), input.meta);

  return ok(member);
}

/** Gives a member another role, then revokes every session the member holds. */
export async function changeRole<A>(
  r: Runtime,
  input: ChangeRoleInput<A>,
): Promise<AuthResult<StoredMember>> {
  const allowed = await authorize(r, 'change-role', input, input.role);

  if (!allowed.ok) return allowed;

  // authorize refuses a missing target for a role change.
  const from = (allowed.value as StoredMember).role;

  // Setting the role the member already holds writes nothing but still
  // revokes, so a retry after a failed revocation finishes the job.
  if (from !== input.role) {
    const write = await r.store.changeRole({
      scope: input.scope,
      userId: input.userId,
      from,
      to: input.role,
      adminRoles: r.settings.adminRoles,
    });

    if (write !== 'done') return refusedWrite(r, input, write, 'change-role');
  }

  await r.core.revokeAllSessions(input.userId, MEMBERSHIP_REVOCATION);
  await r.core.emit(event('membership.role_changed', input, { from, to: input.role }), input.meta);

  return ok({ scope: input.scope, userId: input.userId, role: input.role });
}

/** Removes a member from a scope, then revokes every session the member holds. */
export async function removeMember<A>(
  r: Runtime,
  input: RemoveMemberInput<A>,
): Promise<AuthResult<void>> {
  const allowed = await authorize(r, 'remove', input, undefined);

  if (!allowed.ok) return allowed;

  // authorize refuses a missing target for a removal.
  const from = (allowed.value as StoredMember).role;

  const write = await r.store.removeMember({
    scope: input.scope,
    userId: input.userId,
    from,
    adminRoles: r.settings.adminRoles,
  });

  if (write !== 'done') return refusedWrite(r, input, write, 'remove');

  await r.core.revokeAllSessions(input.userId, MEMBERSHIP_REVOCATION);
  await r.core.emit(event('membership.removed', input, { from }), input.meta);

  return ok();
}

/**
 * Steps 1 and 2: not yourself, a valid role, the actor and the target read
 * from the store, and `canManage` on what was read. Returns the target: null
 * when adding, and always a member for a role change or a removal.
 */
async function authorize<A>(
  r: Runtime,
  action: MemberAction,
  input: MemberActionInput<A>,
  to: string | undefined,
): Promise<AuthResult<StoredMember | null>> {
  const actorId = input.session.userId;

  if (actorId === input.userId) return refused(r, input, 'self_target', 'self_target', action);

  if (to !== undefined && (typeof to !== 'string' || to.length === 0))
    return refused(r, input, 'forbidden', 'invalid_role', action);

  try {
    const actor = await r.store.findMember(input.scope, actorId);

    if (!actor) return await refused(r, input, 'forbidden', 'actor_not_member', action);

    const target = await r.store.findMember(input.scope, input.userId);

    if (action === 'add' ? target !== null : target === null) {
      const reason = action === 'add' ? 'already_member' : 'target_missing';

      return await refused(r, input, 'forbidden', reason, action);
    }

    const from = target?.role;

    if (!(await r.settings.canManage({ actor, action, userId: input.userId, from, to })))
      return await refused(r, input, 'forbidden', 'not_allowed', action);

    return ok(target);
  } catch (error) {
    r.core.logger.error('Membership check failed', {
      action,
      userId: actorId,
      error: describeError(error),
    });

    return refused(r, input, 'forbidden', 'check_failed', action);
  }
}

/** The refusal of a guarded write that did not happen. */
function refusedWrite<A>(
  r: Runtime,
  input: MemberActionInput<A>,
  write: Exclude<MemberWrite, 'done'>,
  action: MemberAction,
): Promise<AuthFailure> {
  if (write === 'last_admin') return refused(r, input, 'last_admin', 'last_admin', action);

  return refused(
    r,
    input,
    'forbidden',
    write === 'missing' ? 'target_missing' : 'target_changed',
    action,
  );
}

/** Writes the audit row of a refusal and returns the failure. */
async function refused<A>(
  r: Runtime,
  input: MemberActionInput<A>,
  code: AuthErrorCode,
  reason: string,
  action: MemberAction,
): Promise<AuthFailure> {
  await r.core.emit(
    { ...event('membership.refused', input, {}), reason, data: data(input, { action }) },
    input.meta,
  );

  return fail(code, reason);
}

function event<A>(
  type:
    'membership.added' | 'membership.role_changed' | 'membership.removed' | 'membership.refused',
  input: MemberActionInput<A>,
  extra: Readonly<Record<string, string>>,
) {
  return { type, userId: input.session.userId, data: data(input, extra) };
}

/** The ids and roles of an audit row. Never an email, never a session id. */
function data<A>(input: MemberActionInput<A>, extra: Readonly<Record<string, string>>) {
  return { scope: input.scope, target: input.userId, ...extra };
}
