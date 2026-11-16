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
 *    epoch along, and finish it through `issueSession` later.
 */
import type { AuthCore } from '../core';
import { normalizeEmail } from '../email';
import { fail, ok, type AuthResult } from '../errors';
import type { RequestMeta } from '../meta';
import { normalizePassword } from '../password/policy';
import type { IssuedSession } from '../plugin-context';
import { accountKey } from '../throttle';
import type { AuthUser } from '../stores';
import { publicUser } from './settings';

export interface LoginInput {
  readonly email: string;
  readonly password: string;
  readonly rememberMe?: boolean;
  readonly captchaToken?: string;
  readonly meta: RequestMeta;
}

export type LoginOutcome<A> =
  | { readonly kind: 'session'; readonly session: IssuedSession<A> }
  | { readonly kind: 'challenge'; readonly challenge: string; readonly methods: readonly string[] };

const NO_USER = '\u0000no-user';

export async function login<U extends AuthUser, A>(core: AuthCore<U, A>, input: LoginInput): Promise<AuthResult<LoginOutcome<A>>> {
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

  const account = accountKey(email);
  const gate = await core.throttle.gateLogin(account, meta.ip);
  const found = await core.users.findCredentialByEmail(email);
  if (!gate.allowed) {
    if (gate.newLock && found) {
      await core.emit({ type: 'account.locked', userId: found.id, data: { until: gate.newLock.until } }, meta);
      await core.mail({ type: 'lockout', to: found.email, userId: found.id, until: new Date(gate.newLock.until) });
    }
    await core.emit({ type: 'login.failure', ...(found ? { userId: found.id } : {}), reason: gate.reason }, meta);
    return fail('invalid_credentials', gate.reason);
  }

  const epoch = await core.sessions.readEpoch(found?.id ?? NO_USER);
  const credential = found ? await core.users.findCredentialById(found.id) : null;
  const verified = await core.verifyPassword(credential?.passwordHash, input.password);
  if (!credential || !verified) {
    const reason = !credential ? 'unknown_user' : credential.passwordHash ? 'wrong_password' : 'password_not_set';
    await core.emit({ type: 'login.failure', ...(credential ? { userId: credential.id } : {}), reason }, meta);
    return fail('invalid_credentials', reason);
  }

  await core.throttle.loginSucceeded(account, meta.ip);
  if (credential.passwordHash && core.hasher.needsRehash(credential.passwordHash)) {
    await rehash(core, credential.id, input.password, meta);
  }

  const user = publicUser(credential);
  for (const hook of core.hooks.loginChallenge) {
    const challenge = await hook({ user, rememberMe, epoch, meta });
    if (challenge) {
      await core.emit({ type: 'login.challenge', userId: user.id, data: { methods: challenge.methods.join(',') } }, meta);
      return ok({ kind: 'challenge', challenge: challenge.challenge, methods: challenge.methods });
    }
  }

  const issued = await core.issueSession(user, { via: 'password', meta, rememberMe, epoch });
  if (!issued.ok) return issued;
  await core.emit({ type: 'login.success', userId: user.id }, meta);
  return ok({ kind: 'session', session: issued.value });
}

/** Upgrades a hash made with older parameters. A failure only costs the upgrade, never the login. */
async function rehash<U extends AuthUser, A>(core: AuthCore<U, A>, userId: string, password: string, meta: RequestMeta) {
  try {
    const hash = await core.hasher.hash(normalizePassword(password));
    if (await core.users.setPasswordHash(userId, hash)) await core.emit({ type: 'password.rehashed', userId }, meta);
  } catch (error) {
    core.logger.warn('Password rehash failed', { userId, error: error instanceof Error ? error.message : String(error) });
  }
}
