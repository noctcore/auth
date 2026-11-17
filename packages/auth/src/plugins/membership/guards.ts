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
 * 4. Only with `revokeSessionsOnChange`: for an attempted change to another
 *    role, or a removal, every session of the member is revoked through the
 *    epoch fence, once before the write and once after it. The first bump runs
 *    before the store decides, so an attempt it refuses (`last_admin`, a stale
 *    or missing target) has still revoked them. A revocation that fails before
 *    the write leaves nothing changed. The bump after the write
 *    catches a login that read the old role between the two: the fence refuses
 *    it at mint, or it was minted on the first bump's epoch and dies now.
 *    Adding a member and setting the role a member already holds never revoke.
 *
 * Every flow first reads the acting session live from the store: a revoked,
 * expired or idle session, or one of another user, acts on nothing.
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

/** Gives a member another role. Revokes the member's sessions only with `revokeSessionsOnChange`. */
export async function changeRole<A>(
  r: Runtime,
  input: ChangeRoleInput<A>,
): Promise<AuthResult<StoredMember>> {
  const allowed = await authorize(r, 'change-role', input, input.role);

  if (!allowed.ok) return allowed;

  // authorize refuses a missing target for a role change.
  const from = (allowed.value as StoredMember).role;

  const member: StoredMember = { scope: input.scope, userId: input.userId, role: input.role };

  // The role the member already holds: nothing to write, nothing to revoke.
  if (from === input.role) return ok(member);

  await revoke(r, input.scope, input.userId);

  const write = await r.store.changeRole({
    scope: input.scope,
    userId: input.userId,
    from,
    to: input.role,
    adminRoles: r.settings.adminRoles,
  });

  if (write !== 'done') return refusedWrite(r, input, write, 'change-role');

  await revoke(r, input.scope, input.userId);
  await r.core.emit(event('membership.role_changed', input, { from, to: input.role }), input.meta);

  return ok(member);
}

/** Removes a member from a scope. Revokes the member's sessions only with `revokeSessionsOnChange`. */
export async function removeMember<A>(
  r: Runtime,
  input: RemoveMemberInput<A>,
): Promise<AuthResult<void>> {
  const allowed = await authorize(r, 'remove', input, undefined);

  if (!allowed.ok) return allowed;

  // authorize refuses a missing target for a removal.
  const from = (allowed.value as StoredMember).role;

  await revoke(r, input.scope, input.userId);

  const write = await r.store.removeMember({
    scope: input.scope,
    userId: input.userId,
    from,
    adminRoles: r.settings.adminRoles,
  });

  if (write !== 'done') return refusedWrite(r, input, write, 'remove');

  await revoke(r, input.scope, input.userId);
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

  const live = await r.core.sessions.findActive(input.session.id);

  if (live?.userId !== actorId)
    return refused(r, input, 'session_expired', 'session_not_live', action);

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

/** Revokes every session of the member, when the app turned revocation on. */
async function revoke(r: Runtime, scope: string, userId: string): Promise<void> {
  if (r.settings.revokeSessionsOnChange)
    await r.core.revokeAllSessions(userId, MEMBERSHIP_REVOCATION, { scope });
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
