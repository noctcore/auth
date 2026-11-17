// Helpers for the email change tests: a signed-in user, a request, the code
// mailed to the new address, and the revert link mailed to the old one.
import { meta, type setup } from './setup';
import type { StoredSession } from '../../src/ports/stores';
import type { RecordingMailer } from '../../src/testing';

type Session = StoredSession<Record<string, never>>;

type Env = {
  auth: Pick<ReturnType<typeof setup>['auth'], 'requestEmailChange' | 'confirmEmailChangeCode'>;
  mailer: RecordingMailer;
};

export const tokenOf = (url: string | undefined) => (url ?? '').split('#')[1] ?? '';

/** Requests a change to `newEmail` and returns the code mailed to it. */
export async function requestCode(env: Env, session: Session, newEmail: string): Promise<string> {
  const requested = await env.auth.requestEmailChange({ session, newEmail, meta: meta() });

  if (!requested.ok) throw new Error(`request failed: ${requested.reason ?? ''}`);

  return env.mailer.last('email-change-confirm')?.code ?? '';
}

/** Requests and confirms a change; returns the re-issued session and the revert token. */
export async function changed(
  env: Env,
  session: Session,
  newEmail: string,
): Promise<{ session: Session; revert: string }> {
  const code = await requestCode(env, session, newEmail);
  const confirmed = await env.auth.confirmEmailChangeCode({ session, code, meta: meta() });

  if (!confirmed.ok) throw new Error(`confirm failed: ${confirmed.reason}`);

  return {
    session: confirmed.value.session.session,
    revert: tokenOf(env.mailer.last('email-changed')?.revertUrl),
  };
}
