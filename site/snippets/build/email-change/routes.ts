import type { RequestMeta, StoredSession } from '@noctcore/auth';
import type { AppAuth } from '../node-server/auth';

type Session = StoredSession<Record<string, never>>;

/**
 * Step 1, from the settings page. The answer is the same whether or not the
 * address has an account: show "check the new address" either way.
 */
export async function requestChange(
  auth: AppAuth,
  session: Session,
  body: { newEmail: string; code?: string },
  meta: RequestMeta,
) {
  const requested = await auth.requestEmailChange({
    session,
    newEmail: body.newEmail,
    // With the two-factor plugin: a code, unless the session holds a step-up.
    ...(body.code ? { secondFactor: body.code } : {}),
    meta,
  });

  // fresh_auth_required: ask for the password (auth.reauthenticate), then retry.
  // second_factor_required: ask for a code, then retry with it.
  if (!requested.ok) return { status: 403, body: { error: requested.code } };

  return { status: 202, body: { expiresAt: requested.value.expiresAt } };
}

/** Step 2: the code from the new address, typed in the same signed-in session. */
export async function confirmChange(auth: AppAuth, session: Session, code: string, meta: RequestMeta) {
  const confirmed = await auth.confirmEmailChangeCode({ session, code, meta });

  if (!confirmed.ok) return { status: 400, body: { error: confirmed.code } };

  // Every other session was signed out; this one was re-issued under a new cookie.
  const cookies = confirmed.value.session ? [confirmed.value.session.cookie] : [];

  return { status: 200, cookies, body: { changed: true } };
}

/**
 * The page behind the revert link in the old address's mail. No session: the
 * person clicking it may be locked out. Read the token from the fragment in the
 * browser and POST it here, so it never reaches a server log or a Referer.
 */
export async function revertChange(auth: AppAuth, token: string, meta: RequestMeta) {
  const reverted = await auth.revertEmailChange({ token, meta });

  if (!reverted.ok) return { status: 400, body: { error: reverted.code } };

  // The password is gone too: send the user to "forgot password" for the restored address.
  return { status: 200, body: { next: '/forgot-password' } };
}
