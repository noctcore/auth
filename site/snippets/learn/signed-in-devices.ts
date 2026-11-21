import { toPublicError, type RequestMeta, type StoredSession } from '@noctcore/auth';
import type { AppAuth } from '../build/node-server/auth';

type Session = StoredSession<Record<string, never>>;

/** "Where you're signed in": sessions named by handle, never store key. */
export function signedInDevices(auth: AppAuth, current: Session) {
  return auth.sessions.list(current);
}

/** Signs out one device. Another device needs a fresh password proof. */
export async function signOutDevice(
  auth: AppAuth,
  input: { current: Session; handle: string; meta: RequestMeta },
) {
  const result = await auth.sessions.revoke({
    session: input.current,
    handle: input.handle,
    meta: input.meta,
  });

  if (!result.ok) return { error: toPublicError(result) };

  // A handle it does not find answers { revoked: false },
  // another user's included.
  return { revoked: result.value.revoked };
}
