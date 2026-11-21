import { serializeCookie, type RequestMeta, type StoredSession } from '@noctcore/auth';
import type { AppAuth } from '../build/node-server/auth';

type Session = StoredSession<Record<string, never>>;

/**
 * "Sign out everywhere". The epoch bump inside revokeAll is the revocation:
 * a login racing it is rolled back at mint or refused at its first request.
 * The sessions it then deletes only free space.
 */
export async function signOutEverywhere(
  auth: AppAuth,
  input: { current: Session; meta: RequestMeta },
) {
  const { cookie } = await auth.sessions.revokeAll({
    session: input.current,
    meta: input.meta,
  });

  // The caller's own cookie is cleared too.
  return { setCookie: serializeCookie(cookie) };
}
