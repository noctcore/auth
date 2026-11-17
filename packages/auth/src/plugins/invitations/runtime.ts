/**
 * What the invitation flows share: the runtime, throttling, the inviter's
 * permission check, and the audit row of a refusal.
 */
import type { AttemptRule, InvitationRequest, InvitationsSettings } from './options';
import type { PluginContext } from '../../core/plugin-context';
import type { AuthEventType } from '../../ports/audit';
import type { InvitationStore, StoredInvitation } from '../../ports/invitations';
import type { AuthUser } from '../../ports/stores';
import { describeError } from '../../shared/describe-error';
import { fail, type AuthErrorCode, type AuthFailure } from '../../shared/errors';
import type { RequestMeta } from '../../shared/meta';

// The plugin is written against any app's user and attribute types.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Context = PluginContext<AuthUser, any>;

export interface Runtime {
  readonly core: Context;
  readonly store: InvitationStore;
  readonly settings: InvitationsSettings;
}

/** The keyed-hash purpose of invitation tokens: never a reset, session or recovery hash. */
export const TOKEN_PURPOSE = 'invitation';
/** The keyed-hash purpose of the per-address throttle key, so no raw address is a counter key. */
const ADDRESS_PURPOSE = 'invitation-address';

/** An invitation as the flows hand it out: never its hash. */
export interface InvitationView {
  readonly id: string;
  readonly scope: string;
  readonly email: string;
  readonly inviterId: string;
  readonly payload: Readonly<Record<string, string>>;
  readonly createdAt: Date;
  readonly expiresAt: Date;
}

export function view(invitation: StoredInvitation): InvitationView {
  return {
    id: invitation.id,
    scope: invitation.scope,
    email: invitation.email,
    inviterId: invitation.inviterId,
    payload: invitation.payload,
    createdAt: new Date(invitation.createdAt),
    expiresAt: new Date(invitation.expiresAt),
  };
}

/** One hit on a window; a `rate_limited` failure (and one audit row per window) when over it. */
export async function limit(
  r: Runtime,
  door: 'ip' | 'inviter' | 'address',
  subject: string,
  rule: AttemptRule,
  meta: RequestMeta,
): Promise<AuthFailure | null> {
  const key = door === 'address' ? r.core.keyedHash(ADDRESS_PURPOSE, subject) : subject;
  const hit = await r.core.throttle.hit(`invitation-${door}:${key}`, rule);

  if (hit.allowed) return null;

  if (hit.firstRefusal)
    await r.core.emit({ type: 'rate_limit.exceeded', reason: `invitation-${door}` }, meta);

  return fail('rate_limited', `rate_limited:invitation-${door}`, {
    retryAfterSeconds: hit.retryAfterSeconds,
  });
}

/** The app's permission check. Throwing refuses; the error is logged without the request. */
export async function allowed(r: Runtime, request: InvitationRequest): Promise<boolean> {
  try {
    return (await r.settings.authorize(request)) === true;
  } catch (error) {
    r.core.logger.error('Invitation permission check failed', {
      action: request.action,
      error: describeError(error),
    });

    return false;
  }
}

/** Writes the audit row of a refusal and returns the failure. */
export async function refused(
  r: Runtime,
  code: AuthErrorCode,
  reason: string,
  userId: string | null,
  meta: RequestMeta,
  type: AuthEventType = 'invitation.refused',
): Promise<AuthFailure> {
  await r.core.emit({ type, ...(userId === null ? {} : { userId }), reason }, meta);

  return fail(code, reason);
}
