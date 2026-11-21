import { toPublicError, type RequestMeta } from '@noctcore/auth';
import type { AppAuth } from '../build/node-server/auth';

/** "Forgot password": the same answer for every address, at once. */
export async function forgotPassword(auth: AppAuth, input: { email: string; meta: RequestMeta }) {
  const result = await auth.requestPasswordReset(input);

  if (!result.ok) return { error: toPublicError(result) };

  // The lookup, the per-account mail limit and the mail run off this path.
  return { status: 'check-your-email' as const };
}

/** The reset page POSTs the token it read from the URL fragment. */
export async function setNewPassword(
  auth: AppAuth,
  input: { token: string; password: string; meta: RequestMeta },
) {
  // Peek, check the password, run the hooks, hash, consume, write.
  // A refused password leaves the link unspent.
  const result = await auth.resetPassword(input);

  if (!result.ok) return { error: toPublicError(result) };

  // Every session was revoked and none is issued: sign in again.
  return { status: 'password-changed' as const };
}
