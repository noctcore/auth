import type { RequestMeta } from '@noctcore/auth';
import type { AppAuth } from '../build/two-factor/auth';

/** A correct password for a user with a factor gives a challenge, never a session. */
export async function signIn(auth: AppAuth, email: string, password: string, meta: RequestMeta) {
  const result = await auth.login({ email, password, meta });

  if (!result.ok) return { error: result.code };
  if (result.value.kind === 'session') return { session: result.value.session };

  // The challenge lives five minutes and takes five codes.
  return { challenge: result.value.challenge, methods: result.value.methods };
}

/** The code from the authenticator app, typed on the next screen. */
export async function answer(auth: AppAuth, challenge: string, code: string, meta: RequestMeta) {
  const result = await auth.twoFactor.verifyChallenge({
    challenge,
    proof: { kind: 'totp', code },
    rememberDevice: false,
    meta,
  });

  // A wrong, replayed or locked code, and a spent or unknown challenge,
  // all answer `invalid_second_factor`. The reason goes to the audit row.
  if (!result.ok) return { error: result.code };

  return { session: result.value.session };
}
