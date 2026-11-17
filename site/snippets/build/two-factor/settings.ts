import type { RequestMeta, StoredSession } from '@noctcore/auth';
import type { AppAuth } from './auth';

type Session = StoredSession<Record<string, never>>;

/** Settings, step 1: a pending secret to show as a QR code (from `uri`) and as text. */
export async function startEnrollment(auth: AppAuth, session: Session, meta: RequestMeta) {
  const started = await auth.twoFactor.enroll({ session, meta });

  if (!started.ok) return { status: 403, body: { error: started.code } };

  return { status: 200, body: { uri: started.value.uri, secret: started.value.secret } };
}

/** Settings, step 2: the first code turns it on and returns the recovery codes, once. */
export async function confirmEnrollment(auth: AppAuth, session: Session, code: string, meta: RequestMeta) {
  const confirmed = await auth.twoFactor.confirmEnrollment({
    session,
    code,
    revokeOtherSessions: true,
    meta,
  });

  if (!confirmed.ok) return { status: 400, body: { error: confirmed.code } };

  const cookies = confirmed.value.session ? [confirmed.value.session.cookie] : [];

  return { status: 200, cookies, body: { recoveryCodes: confirmed.value.recoveryCodes } };
}

/** Any sensitive action of your own: fresh authentication plus a recent second-factor proof. */
export async function deleteProject(auth: AppAuth, session: Session, projectId: string) {
  const allowed = await auth.twoFactor.requireStepUp(session);

  // The client asks for the password (fresh_auth_required) or a code (second_factor_required), then retries.
  if (!allowed.ok) return { status: 403, body: { error: allowed.code } };

  return { status: 200, body: { deleted: projectId } };
}

/** The code prompt behind that 403. */
export async function stepUp(auth: AppAuth, session: Session, code: string, meta: RequestMeta) {
  const proved = await auth.twoFactor.stepUp({ session, proof: { kind: 'totp', code }, meta });

  return proved.ok
    ? { status: 200, body: { until: proved.value.expiresAt } }
    : { status: 401, body: { error: proved.code } };
}
