/**
 * Flows that prove the current password of a signed-in user: re-authenticating
 * (a step-up before a sensitive action) and changing the password. A wrong
 * password spends the account-wide lockout budget, like a failed login.
 */
import { sendLockNotice } from './lock-notice';
import { RESET_PURPOSES, publicUser } from './settings';
import type { AuthCore } from '../core/auth-core';
import { firstRefusal } from '../core/hooks';
import type { IssuedSession } from '../core/plugin-context';
import type { AuthUser, StoredSession } from '../ports/stores';
import { fail, ok, type AuthResult } from '../shared/errors';
import type { RequestMeta } from '../shared/meta';
import { accountKey } from '../throttle/counter-keys';

/**
 * Proves the password again and re-issues the session with a fresh
 * `authenticatedAt`. A wrong password spends the account-wide lockout budget.
 */
export async function reauthenticate<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  input: { session: StoredSession<A>; password: string; meta: RequestMeta },
): Promise<AuthResult<IssuedSession<A>>> {
  const proved = await proveCurrentPassword(
    core,
    input.session,
    input.password,
    input.meta,
    'reauthenticate',
  );

  if (!proved.ok) return proved;

  await core.sessions.revoke(input.session.userId, [input.session.id]);

  return core.issueSession(proved.value, {
    via: 'reauthenticate',
    meta: input.meta,
    inherit: input.session,
    epoch: input.session.epoch,
  });
}

export async function changePassword<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  input: {
    session: StoredSession<A>;
    currentPassword: string;
    newPassword: string;
    secondFactor?: string;
    meta: RequestMeta;
  },
): Promise<AuthResult<IssuedSession<A>>> {
  const { session, meta } = input;

  const proved = await proveCurrentPassword(
    core,
    session,
    input.currentPassword,
    meta,
    'password-change',
  );

  if (!proved.ok) return proved;

  const user = proved.value;

  const refusal = await firstRefusal(core.hooks.beforePasswordChange, {
    user,
    session,
    secondFactor: input.secondFactor,
    meta,
  });

  if (refusal) {
    await core.emit(
      { type: 'password.change_failed', userId: user.id, reason: refusal.reason },
      meta,
    );

    return fail(refusal.code, refusal.reason);
  }

  const hashed = await core.hashNewPassword(input.newPassword, meta);

  if (!hashed.ok) {
    await core.emit(
      { type: 'password.change_failed', userId: user.id, reason: hashed.reason },
      meta,
    );

    return hashed;
  }

  const written = await core.users.setPasswordHash(user.id, hashed.value);

  if (!written) return fail('session_expired', 'user_missing');

  // Stricter than the auth guide's "offer it": every session ends, the
  // current one is re-issued, and the change is mailed to the owner.
  await core.revokeAllSessions(user.id, 'password-change');
  await core.tokens.revokeAll(user.id, RESET_PURPOSES);
  await core.emit({ type: 'password.changed', userId: user.id }, meta);

  await core.mail({
    type: 'password-changed',
    to: user.email,
    userId: user.id,
    at: new Date(core.clock.now()),
  });

  return core.issueSession(user, { via: 'password-change', meta, inherit: session });
}

async function proveCurrentPassword<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  session: StoredSession<A>,
  password: string,
  meta: RequestMeta,
  door: 'password-change' | 'reauthenticate',
): Promise<AuthResult<U>> {
  const limited = await core.rateLimit(door, session.userId, meta);

  if (limited) return limited;

  const credential = await core.users.findCredentialById(session.userId);

  if (!credential) return fail('session_expired', 'user_missing');
  if (!credential.passwordHash) return fail('password_not_set', 'password_not_set');

  const correct = await core.verifyPassword(credential.passwordHash, password);

  if (!correct) {
    const { newLock } = await core.throttle.recordFailure(accountKey(credential.email));

    if (newLock) await sendLockNotice(core, credential, newLock.until, meta);

    await core.emit(
      { type: 'password.change_failed', userId: credential.id, reason: `wrong_password:${door}` },
      meta,
    );

    return fail('invalid_credentials', 'wrong_password');
  }

  return ok(publicUser(credential));
}
