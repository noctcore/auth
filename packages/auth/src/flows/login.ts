/**
 * Password login.
 *
 * Every refusal after the captcha and the door limit answers
 * `invalid_credentials`: an unknown address, a wrong password, a locked
 * account and an account a hook refused all look the same, and known and
 * unknown addresses do the same work (the lockout counters are keyed on the
 * address, and an unknown address pays for a full password verify).
 *
 * Order matters:
 * 1. the lockout gate reserves an attempt BEFORE the password is checked, so
 *    parallel guesses cannot overrun the budget;
 * 2. the revocation epoch is read BEFORE the password hash, so a password
 *    change that lands during the login invalidates the session it mints;
 * 3. a second-factor plugin can turn the login into a challenge, carrying the
 *    epoch along, and finish it through `issueSession` later;
 * 4. a locked account still pays for the password verify, and the lock notice
 *    (audit row and owner mail) runs off the response path.
 *
 * Every issued session carries a trusted-device cookie (`session.deviceCookie`),
 * minted in `issueSession`, so never before the last factor. Presenting it on a
 * later login lets a correct password through an account lock (see throttle/throttle.ts).
 */
import { sendLockNotice } from './lock-notice';
import { rehash } from './rehash';
import { publicUser } from './settings';
import type { AuthCore } from '../core/auth-core';
import type { IssuedSession } from '../core/plugin-context';
import { NO_SUCH_USER_ID, type AuthUser } from '../ports/stores';
import { normalizeEmail } from '../shared/email';
import { fail, ok, type AuthResult } from '../shared/errors';
import type { RequestMeta } from '../shared/meta';
import { accountKey } from '../throttle/counter-keys';

export interface LoginInput {
  readonly email: string;
  readonly password: string;
  readonly rememberMe?: boolean;
  readonly captchaToken?: string;
  /** The value of the trusted-device cookie, if the request carried one (`auth.readDeviceToken`). */
  readonly deviceToken?: string | null;
  readonly meta: RequestMeta;
}

export type LoginOutcome<A> =
  | { readonly kind: 'session'; readonly session: IssuedSession<A> }
  | { readonly kind: 'challenge'; readonly challenge: string; readonly methods: readonly string[] };

type Credential = { readonly id: string; readonly email: string } | null;

export async function login<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  input: LoginInput,
): Promise<AuthResult<LoginOutcome<A>>> {
  const { meta } = input;
  const rememberMe = input.rememberMe ?? false;
  const captcha = await core.checkCaptcha('login', input.captchaToken, meta);

  if (captcha) {
    await core.emit({ type: 'login.failure', reason: captcha.reason }, meta);

    return captcha;
  }

  const limited = await core.rateLimit('login', meta.ip, meta);

  if (limited) return limited;

  const email = normalizeEmail(input.email);

  if (!email) {
    await core.emit({ type: 'login.failure', reason: 'invalid_email' }, meta);

    return fail('invalid_credentials', 'invalid_email');
  }

  // Known and unknown addresses, locked or not, make the same store calls and
  // pay for the same password verify.
  const account = accountKey(email);
  const found = await core.users.findCredentialByEmail(email);
  const epoch = await core.sessions.readEpoch(found?.id ?? NO_SUCH_USER_ID);
  const credential = await core.users.findCredentialById(found?.id ?? NO_SUCH_USER_ID);
  const deviceId = core.verifyDevice(credential?.id ?? NO_SUCH_USER_ID, epoch, input.deviceToken);
  const gate = await core.throttle.gateLogin(account, meta.ip, deviceId);
  const verified = await core.verifyPassword(credential?.passwordHash, input.password);

  if (!gate.allowed) {
    notifyLock(core, credential, gate.newLock, meta);

    await emitFailure(core, credential, gate.reason, meta);

    return fail('invalid_credentials', gate.reason);
  }

  if (!credential || !verified) {
    // A device token lets only a correct password through a lock; a wrong one
    // counts against the devices' shared failures and the account-wide budget.
    if (gate.viaDevice) {
      const { newLock } = await core.throttle.deviceFailed(account);

      notifyLock(core, credential, newLock, meta);
    }

    const reason = !credential
      ? 'unknown_user'
      : credential.passwordHash
        ? 'wrong_password'
        : 'password_not_set';

    await emitFailure(core, credential, reason, meta);

    return fail('invalid_credentials', reason);
  }

  await core.throttle.loginSucceeded(account, meta.ip, gate.viaDevice ? deviceId : null);

  if (credential.passwordHash && core.hasher.needsRehash(credential.passwordHash)) {
    await rehash(core, credential.id, credential.passwordHash, input.password, meta);
  }

  const user = publicUser(credential);

  for (const hook of core.hooks.loginChallenge) {
    const challenge = await hook({ user, rememberMe, epoch, meta });

    if (!challenge) continue;

    // No device cookie yet: it comes with the session, after every factor.
    const methods = challenge.methods.join(',');

    await core.emit({ type: 'login.challenge', userId: user.id, data: { methods } }, meta);

    return ok({ kind: 'challenge', challenge: challenge.challenge, methods: challenge.methods });
  }

  const issued = await core.issueSession(user, { via: 'password', meta, rememberMe, epoch });

  if (!issued.ok) return issued;

  await core.emit({ type: 'login.success', userId: user.id }, meta);

  return ok({ kind: 'session', session: issued.value });
}

/** The audit row of a refused login; the user id only when the address belongs to an account. */
async function emitFailure<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  credential: Credential,
  reason: string,
  meta: RequestMeta,
): Promise<void> {
  await core.emit(
    { type: 'login.failure', ...(credential ? { userId: credential.id } : {}), reason },
    meta,
  );
}

/** A new lock's notice, off the response path so a known account answers no slower. */
function notifyLock<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  credential: Credential,
  newLock: { until: number } | undefined,
  meta: RequestMeta,
): void {
  if (!newLock || !credential) return;

  core.background('lockout notice', () => sendLockNotice(core, credential, newLock.until, meta));
}
