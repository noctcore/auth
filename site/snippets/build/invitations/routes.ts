import { toPublicError, type RequestMeta, type StoredSession } from '@noctcore/auth';
import type { AppAuth } from './auth';

type Session = StoredSession<Record<string, never>>;

interface Reply {
  readonly status: number;
  readonly body: unknown;
}

/** The status each invitation refusal is sent with. */
const STATUS: Record<string, number> = {
  forbidden: 403,
  invalid_token: 400,
  email_in_use: 409,
  rate_limited: 429,
};

function refusal(result: Parameters<typeof toPublicError>[0]): Reply {
  return { status: STATUS[result.code] ?? 400, body: toPublicError(result) };
}

/** POST /orgs/:orgId/invitations { email, role } */
export async function invite(
  auth: AppAuth,
  session: Session,
  orgId: string,
  body: { email: string; role: string },
  meta: RequestMeta,
): Promise<Reply> {
  const result = await auth.invitations.create({
    session,
    scope: orgId,
    email: body.email,
    payload: { role: body.role },
    meta,
  });

  if (!result.ok) return refusal(result);

  // `invitation` is null when one is already pending for this address: nothing was sent.
  return { status: 202, body: { invitation: result.value.invitation } };
}

/** POST /invitations/accept { token }, from the page at /invite, signed in. */
export async function accept(
  auth: AppAuth,
  session: Session,
  token: string,
  meta: RequestMeta,
): Promise<Reply> {
  const result = await auth.invitations.accept({ session, token, meta });

  return result.ok ? { status: 200, body: { scope: result.value.scope } } : refusal(result);
}

/** POST /invitations/register { token, password }, from the page at /invite, signed out. */
export async function register(
  auth: AppAuth,
  token: string,
  password: string,
  meta: RequestMeta,
): Promise<Reply & { readonly sessionToken?: string }> {
  const result = await auth.invitations.register({ token, password, meta });

  if (!result.ok) return refusal(result);

  // Set the session cookie from `sessionToken` the way your login route does.
  return {
    status: 201,
    body: { scope: result.value.invitation.scope },
    sessionToken: result.value.session.token,
  };
}
