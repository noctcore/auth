/**
 * Flows for a signed-in user: validating requests, fresh authentication,
 * changing the password and managing sessions.
 *
 * Session management is a high-privilege action (the auth guide's advice):
 * revoking another device's session, or every other session, needs a fresh
 * credential proof, so a stolen session cannot keep signing the owner out.
 * Signing out of the current device, or everywhere including it, needs none.
 */
import type { Clock } from '../ports/clock';
import { createBlankSessionCookie, type CookieSpec } from '../http/cookie';
import type { AuthCore } from '../core/auth-core';
import { fail, ok, type AuthResult } from '../shared/errors';
import { firstRefusal } from '../core/hooks';
import type { RequestMeta } from '../shared/meta';
import type { IssuedSession } from '../core/plugin-context';
import { accountKey } from '../throttle/throttle';
import type { AuthUser, StoredSession } from '../ports/stores';
import { RESET_PURPOSES, publicUser, type FlowSettings } from './settings';

export async function validateRequest<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  input: { token: string | null | undefined; meta?: RequestMeta; touch?: boolean },
): Promise<AuthResult<StoredSession<A>>> {
  const result = await core.sessions.validate(input.token, { touch: input.touch ?? true });

  if (!result.ok) return fail('session_expired', `session_${result.reason}`);

  const refusal = await firstRefusal(core.hooks.onSessionValidate, {
    session: result.session,
    meta: input.meta,
  });

  if (refusal) {
    const ids = await core.sessions.revoke(result.session.userId, [result.session.id]);

    await core.emit(
      { type: 'session.revoked', userId: result.session.userId, reason: refusal.reason },
      input.meta,
    );

    await core.notifyRevoked(result.session.userId, ids, refusal.reason);

    return fail(
      refusal.code === 'invalid_credentials' ? 'session_expired' : refusal.code,
      refusal.reason,
    );
  }

  return ok(result.session);
}

/** Refuses when the session's last credential proof is older than `freshAuthAge`. */
export function requireFreshAuth<A>(
  core: { readonly clock: Clock },
  settings: FlowSettings,
  session: StoredSession<A>,
): AuthResult<void> {
  return core.clock.now() - session.authenticatedAt <= settings.freshAuthAgeMs
    ? ok()
    : fail('fresh_auth_required', 'stale_authentication');
}

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

  if (!(await core.users.setPasswordHash(user.id, hashed.value)))
    return fail('session_expired', 'user_missing');

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

  if (!(await core.verifyPassword(credential.passwordHash, password))) {
    const { newLock } = await core.throttle.recordFailure(accountKey(credential.email));

    if (newLock) {
      await core.emit(
        { type: 'account.locked', userId: credential.id, data: { until: newLock.until } },
        meta,
      );

      await core.mail({
        type: 'lockout',
        to: credential.email,
        userId: credential.id,
        until: new Date(newLock.until),
      });
    }

    await core.emit(
      { type: 'password.change_failed', userId: credential.id, reason: `wrong_password:${door}` },
      meta,
    );

    return fail('invalid_credentials', 'wrong_password');
  }

  return ok(publicUser(credential));
}

export interface SessionSummary {
  readonly id: string;
  readonly current: boolean;
  readonly createdAt: number;
  readonly lastActiveAt: number;
  readonly expiresAt: number;
  readonly ip: string;
  readonly userAgent: string;
}

export async function listSessions<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  session: StoredSession<A>,
): Promise<SessionSummary[]> {
  const active = await core.sessions.listActive(session.userId);

  return active
    .sort((a, b) => b.lastActiveAt - a.lastActiveAt)
    .map((s) => ({
      id: s.id,
      current: s.id === session.id,
      createdAt: s.createdAt,
      lastActiveAt: s.lastActiveAt,
      expiresAt: s.expiresAt,
      ip: s.ip,
      userAgent: s.userAgent,
    }));
}

/** Revokes one session of the caller. Another device's session needs fresh authentication. */
export async function revokeSession<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  settings: FlowSettings,
  input: { session: StoredSession<A>; id: string; meta: RequestMeta },
): Promise<AuthResult<{ revoked: boolean }>> {
  if (input.id !== input.session.id) {
    const fresh = requireFreshAuth(core, settings, input.session);

    if (!fresh.ok) return fresh;
  }

  const ids = await core.sessions.revoke(input.session.userId, [input.id]);

  if (ids.length > 0) {
    await core.emit(
      { type: 'session.revoked', userId: input.session.userId, reason: 'revoke-one' },
      input.meta,
    );

    await core.notifyRevoked(input.session.userId, ids, 'revoke-one');
  }

  return ok({ revoked: ids.length > 0 });
}

/** Signs out every other device (needs fresh authentication): revokes all sessions and re-issues the caller's. */
export async function revokeOtherSessions<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  settings: FlowSettings,
  input: { session: StoredSession<A>; meta: RequestMeta },
): Promise<AuthResult<IssuedSession<A>>> {
  // High privilege, like revoking one device: a stolen session must not be
  // able to sign the owner out everywhere.
  const fresh = requireFreshAuth(core, settings, input.session);

  if (!fresh.ok) return fresh;

  const user = await core.users.findById(input.session.userId);

  if (!user) return fail('session_expired', 'user_missing');

  await core.revokeAllSessions(user.id, 'revoke-others');

  return core.issueSession(user, {
    via: 'revoke-others',
    meta: input.meta,
    inherit: input.session,
    authenticatedAt: input.session.authenticatedAt,
  });
}

/** Signs out everywhere, this device included. */
export async function revokeAllSessions<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  input: { session: StoredSession<A>; meta: RequestMeta },
): Promise<{ cookie: CookieSpec }> {
  await core.revokeAllSessions(input.session.userId, 'revoke-all');

  return { cookie: createBlankSessionCookie(core.cookie, input.meta.origin) };
}

/** Ends the session the token names. Always returns the blank cookie, even for an unknown token. */
export async function logout<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  input: { token: string | null | undefined; meta: RequestMeta },
): Promise<{ cookie: CookieSpec }> {
  const ended = await core.sessions.revokeToken(input.token);

  if (ended) {
    await core.emit({ type: 'logout', userId: ended.userId }, input.meta);
    await core.notifyRevoked(ended.userId, [ended.id], 'logout');
  }

  return { cookie: createBlankSessionCookie(core.cookie, input.meta.origin) };
}
