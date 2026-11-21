import { toPublicError, type RequestMeta, type StoredSession } from '@noctcore/auth';
import type { AppAuth } from '../build/node-server/auth';

type Session = StoredSession<Record<string, never>>;

/**
 * POST only, from the click on a page that read the token from its URL
 * fragment and did nothing on load. A mail scanner that fetches the link
 * never reaches this route.
 */
export async function confirmEmail(
  auth: AppAuth,
  input: { token: string; session: Session | null; meta: RequestMeta },
) {
  const result = await auth.verifyEmailLink(input);

  // Opened in another account's session: refused, and left unspent.
  if (!result.ok) return { error: toPublicError(result) };

  // Signed in as this account: every session was revoked and this one
  // re-issued. With linkWithoutSession and no session, nobody is signed in.
  return { verified: true, session: result.value.session ?? null };
}
