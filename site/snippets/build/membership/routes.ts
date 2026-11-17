import { toPublicError, type RequestMeta, type StoredSession } from '@noctcore/auth';
import { members, type AppAuth } from './auth';

interface Reply {
  readonly status: number;
  readonly body: unknown;
}

/** The status each membership refusal is sent with. */
const STATUS: Record<string, number> = {
  self_target: 403,
  last_admin: 409,
  forbidden: 403,
};

/** POST /orgs/:orgId/members/:userId/role { role } */
export async function changeRole(
  auth: AppAuth,
  session: StoredSession<Record<string, never>>,
  orgId: string,
  userId: string,
  role: string,
  meta: RequestMeta,
): Promise<Reply> {
  const result = await auth.membership.changeRole({ session, scope: orgId, userId, role, meta });

  if (!result.ok) return { status: STATUS[result.code] ?? 400, body: toPublicError(result) };

  // The member's sessions are already revoked: they sign in again under the new role.
  return { status: 200, body: { member: result.value } };
}

/** DELETE /orgs/:orgId/members/:userId */
export async function removeMember(
  auth: AppAuth,
  session: StoredSession<Record<string, never>>,
  orgId: string,
  userId: string,
  meta: RequestMeta,
): Promise<Reply> {
  const result = await auth.membership.remove({ session, scope: orgId, userId, meta });

  if (!result.ok) return { status: STATUS[result.code] ?? 400, body: toPublicError(result) };

  return { status: 204, body: null };
}

/** Creating an organisation: its creator becomes the first owner, straight through the store. */
export async function createOrganisation(orgId: string, creatorId: string): Promise<void> {
  await members.addMember({ scope: orgId, userId: creatorId, role: 'owner' });
}
