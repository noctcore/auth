import type { RequestMeta } from '@noctcore/auth';
import type { AppAuth } from './auth';

/** POST /login: a session, or a challenge the browser answers on the next screen. */
export async function login(auth: AppAuth, body: { email: string; password: string }, meta: RequestMeta) {
  const result = await auth.login({ email: body.email, password: body.password, meta });

  if (!result.ok) return { status: 401, body: { error: result.code } };

  if (result.value.kind === 'challenge') {
    // `methods` is ['enroll'] for a user the app requires a factor of who has none yet.
    return { status: 200, body: { challenge: result.value.challenge, methods: result.value.methods } };
  }

  return { status: 200, cookies: [result.value.session.cookie], body: { ok: true } };
}

/** POST /login/second-factor: a code, a recovery code, or the trusted-device cookie. */
export async function secondFactor(
  auth: AppAuth,
  body: { challenge: string; code?: string; recoveryCode?: string; rememberDevice?: boolean },
  cookieHeader: string | null,
  meta: RequestMeta,
) {
  const device = auth.twoFactor.readTrustedDeviceToken(cookieHeader);
  const proof = body.recoveryCode
    ? ({ kind: 'recovery-code', code: body.recoveryCode } as const)
    : body.code
      ? ({ kind: 'totp', code: body.code } as const)
      : ({ kind: 'trusted-device', token: device } as const);

  const result = await auth.twoFactor.verifyChallenge({
    challenge: body.challenge,
    proof,
    rememberDevice: body.rememberDevice === true,
    meta,
  });

  // One answer for every refusal: the reason is in your audit log, not the response.
  if (!result.ok) return { status: 401, body: { error: result.code } };

  const { session, trustedDevice, recoveryCodes } = result.value;
  const cookies = trustedDevice ? [session.cookie, trustedDevice.cookie] : [session.cookie];

  // recoveryCodes is set only when this challenge was an enrollment: show them once.
  return { status: 200, cookies, body: { ok: true, recoveryCodes } };
}
