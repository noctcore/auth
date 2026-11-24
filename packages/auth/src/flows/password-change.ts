/**
 * Flows that prove the current password of a signed-in user: re-authenticating
 * (a step-up before a sensitive action) and changing the password. By default
 * each attempt spends login's lockout budget, so guesses through login and
 * both doors add up (see `proveCurrentPassword`); with
 * `throttle.lockout.sessionProofs: 'door'` only the door's own limit counts,
 * so a stolen session cannot lock the owner out of sign-in (`proveAtDoor`).
 */
import { sendLockNotice } from './lock-notice';
import { gateRefusal } from './login';
import { permanentLockRefusal } from './permanent-lock';
import { closeAfterWrite, writePasswordHash } from './password-write';
import { publicUser } from './settings';
import type { AuthCore } from '../core/auth-core';
import { firstRefusal } from '../core/hooks';
import type { IssuedSession } from '../core/plugin-context';
import { mailMeta } from '../ports/mail';
import type { AuthUser, StoredSession, WithPasswordHash } from '../ports/stores';
import { sha256Hex } from '../crypto/hash';
import { fail, ok, type AuthResult } from '../shared/errors';
import type { RequestMeta } from '../shared/meta';
import { accountKey } from '../throttle/counter-keys';

/**
 * Proves the password again and re-issues the session with a fresh
 * `authenticatedAt`. The attempt spends login's lockout budget.
 */
export async function reauthenticate<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  input: { session: StoredSession<A>; password: string; meta: RequestMeta },
): Promise<AuthResult<IssuedSession<A>>> {
  const live = await core.confirmLiveSession(input.session);

  if (!live) return fail('session_expired', 'session_not_active');

  const proved = await proveCurrentPassword(
    core,
    live,
    input.password,
    input.meta,
    'reauthenticate',
  );

  if (!proved.ok) return proved;

  await core.sessions.revoke(live.userId, [live.id]);

  return core.issueSession(proved.value, {
    via: 'reauthenticate',
    meta: input.meta,
    inherit: live,
    epoch: live.epoch,
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
  const { meta } = input;
  // Read live before anything is written or revoked: only a session that is
  // still active can be the one this change re-issues.
  const session = await core.confirmLiveSession(input.session);

  if (!session) return fail('session_expired', 'session_not_active');

  const proved = await proveCurrentPassword(
    core,
    session,
    input.currentPassword,
    meta,
    'password-change',
  );

  if (!proved.ok) return proved;

  const user = proved.value;

  // The new password is checked before the hooks, so one the policy refuses
  // does not spend what a hook asked for (a second factor's code, say).
  const hashed = await core.hashNewPassword(input.newPassword, meta);

  if (!hashed.ok) {
    await core.emit(
      { type: 'password.change_failed', userId: user.id, reason: hashed.reason },
      meta,
    );

    return hashed;
  }

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

  // Every reset link and ticket dies before the write (password-write.ts).
  const written = await writePasswordHash(core, user.id, hashed.value);

  if (!written) return fail('session_expired', 'user_missing');

  // Stricter than the auth guide's "offer it": every session ends, the
  // current one is re-issued, and the change is mailed to the owner.
  // The sessions end even when the sweep fails; a failure of either is
  // thrown once the owner has been told (password-write.ts).
  const closed = await closeAfterWrite(core, user.id, 'password-change');

  await core.emit({ type: 'password.changed', userId: user.id }, meta);

  core.mail({
    type: 'password-changed',
    to: user.email,
    userId: user.id,
    at: new Date(core.clock.now()),
    ...mailMeta(meta),
  });

  if (closed.failed) throw closed.error;

  return core.issueSession(user, { via: 'password-change', meta, inherit: session });
}

/**
 * Each attempt reserves a slot in login's lockout budget BEFORE the verify,
 * through the same gate and keys as login (`Throttle.gateLogin`): the
 * per (account, IP) and account-wide budgets while the account is unlocked,
 * so guesses through login and both doors add up. Under a lock the live
 * session stands in for a trusted device: the attempt reserves a slot in
 * the session's own budget and in the budget shared by every trusted device
 * of the account (5 per 15 min by default), so the owner can still step up
 * under a lock an outsider set, while a stolen session gets no more checks
 * than a stolen device cookie would at login. Refusals answer like login's
 * (`invalid_credentials`, or `account_locked` with `revealLocked`) after the
 * same password verify, so a spent budget and a wrong password take the same
 * work. The per-door rate limit still applies first. With
 * `sessionProofs: 'door'` the lockout is left out entirely (`proveAtDoor`).
 */
async function proveCurrentPassword<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  session: StoredSession<A>,
  password: string,
  meta: RequestMeta,
  door: 'password-change' | 'reauthenticate',
): Promise<AuthResult<U>> {
  const limited = await core.rateLimit(door, session.userId, meta);

  if (limited) return limited;

  const locked = await permanentLockRefusal(core, session.userId, 'session');

  if (locked) return locked;

  const credential = await core.users.findCredentialById(session.userId);

  if (!credential) return fail('session_expired', 'user_missing');
  if (!credential.passwordHash) return fail('password_not_set', 'password_not_set');

  if (core.throttle.sessionProofs === 'door')
    return proveAtDoor(core, credential, credential.passwordHash, password, meta, door);

  const account = accountKey(credential.email);
  const deviceId = sessionDeviceId(session.id);
  const gate = await core.throttle.gateLogin(account, meta.ip, deviceId, credential.id);
  const correct = await core.verifyPassword(credential.passwordHash, password);

  if (!gate.allowed) {
    if (gate.newLock) await sendLockNotice(core, credential, gate.newLock, meta);

    await emitChangeFailed(core, credential.id, `${gate.reason}:${door}`, meta);

    return gateRefusal(core, gate);
  }

  if (!correct) {
    // Under a lock a wrong password keeps its device slots and also counts
    // against the account-wide budget; otherwise the gate already counted it.
    if (gate.viaDevice) {
      const { newLock } = await core.throttle.deviceFailed(account, credential.id);

      if (newLock) await sendLockNotice(core, credential, newLock, meta);
    }

    await emitChangeFailed(core, credential.id, `wrong_password:${door}`, meta);

    return fail('invalid_credentials', 'wrong_password');
  }

  await core.throttle.loginSucceeded(account, meta.ip, gate.viaDevice ? deviceId : null);

  // The caller holds a session from a completed sign-in, so a correct password
  // here is not a step toward one: with `countSuccesses` false its slot comes
  // back now. A device slot was handed back above, and owed nothing.
  if (!gate.viaDevice) await core.throttle.refundSuccess(account);

  return ok(publicUser(credential));
}

/**
 * `sessionProofs: 'door'`: the door's per-user limit (checked by the caller)
 * is the only budget. No lockout counter is read or written, so a wrong
 * password cannot lock the owner out of sign-in or climb the permanent tier,
 * and a temporary lock does not refuse a correct one. The verify is the same
 * work either way.
 */
async function proveAtDoor<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  credential: WithPasswordHash<U>,
  hash: string,
  password: string,
  meta: RequestMeta,
  door: 'password-change' | 'reauthenticate',
): Promise<AuthResult<U>> {
  if (!(await core.verifyPassword(hash, password))) {
    await emitChangeFailed(core, credential.id, `wrong_password:${door}`, meta);

    return fail('invalid_credentials', 'wrong_password');
  }

  return ok(publicUser(credential));
}

/**
 * The trusted-device id a live session stands in for under a lock. Hashed,
 * so the counter store never holds a session's store key.
 */
function sessionDeviceId(sessionId: string): string {
  return sha256Hex(`session-device:${sessionId}`);
}

async function emitChangeFailed<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  userId: string,
  reason: string,
  meta: RequestMeta,
): Promise<void> {
  await core.emit({ type: 'password.change_failed', userId, reason }, meta);
}
