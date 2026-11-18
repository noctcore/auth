/**
 * A signed-in user's sessions: listing them, revoking one, every other one, or
 * all of them, and signing out.
 *
 * Session management is a high-privilege action (the auth guide's advice):
 * revoking another device's session, or every other session, needs a fresh
 * credential proof, so a stolen session cannot keep signing the owner out.
 * Signing out of the current device, or everywhere including it, needs none.
 * Signing out of other devices or everywhere also voids a pending email change.
 *
 * A client only ever sees a session's public handle (`AuthCore.sessionHandle`),
 * never its store key: the list shows handles and revoke takes one.
 */
import { requireFreshAuth } from './session-validation';
import { PURPOSE, type FlowSettings } from './settings';
import type { AuthCore } from '../core/auth-core';
import type { IssuedSession } from '../core/plugin-context';
import { createBlankSessionCookie, type CookieSpec } from '../http/cookie';
import type { AuthUser, StoredSession } from '../ports/stores';
import { fail, ok, type AuthResult } from '../shared/errors';
import type { RequestMeta } from '../shared/meta';

/**
 * What signing out of other devices, or of all of them, voids: a pending email
 * change, so one started from a session the owner just ended dies with it.
 */
const SIGN_OUT_PURPOSES: readonly string[] = [PURPOSE.emailChange];

export interface SessionSummary {
  /**
   * The session's public handle: an HMAC of its store key under a key derived
   * from the server secret. Pass it to `sessions.revoke`. Never the store key.
   */
  readonly handle: string;
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
      handle: core.sessionHandle(s.id),
      current: s.id === session.id,
      createdAt: s.createdAt,
      lastActiveAt: s.lastActiveAt,
      expiresAt: s.expiresAt,
      ip: s.ip,
      userAgent: s.userAgent,
    }));
}

/**
 * Revokes the caller's session that `handle` names. Another device's session
 * needs fresh authentication. A handle that names none of the caller's live
 * sessions (garbage, stale, or another user's) answers `{ revoked: false }`,
 * the same as a session that is already gone, so revoke cannot be used to
 * learn whether a handle belongs to anyone.
 */
export async function revokeSession<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  settings: FlowSettings,
  input: { session: StoredSession<A>; handle: string; meta: RequestMeta },
): Promise<AuthResult<{ revoked: boolean }>> {
  const userId = input.session.userId;

  // Another device's session is high privilege: freshness is read from the
  // live copy of the caller's session, not from the object passed in. The
  // check comes before any lookup, so a stale session gets the same refusal
  // for every handle that is not its own.
  if (input.handle !== core.sessionHandle(input.session.id)) {
    const fresh = await core.requireFreshLiveSession(input.session);

    if (!fresh.ok) return fresh;
  }

  // Only the caller's own sessions are searched: a handle is never resolved
  // across users, so another user's handle finds nothing here.
  const target = (await core.sessions.listActive(userId)).find(
    (s) => core.sessionHandle(s.id) === input.handle,
  );

  const ids = target ? await core.sessions.revoke(userId, [target.id]) : [];

  if (ids.length > 0) {
    await core.emit({ type: 'session.revoked', userId, reason: 'revoke-one' }, input.meta);

    await core.notifyRevoked(userId, ids, 'revoke-one');
  }

  return ok({ revoked: ids.length > 0 });
}

/** Signs out every other device (needs fresh authentication): revokes all sessions and re-issues the caller's. */
export async function revokeOtherSessions<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  settings: FlowSettings,
  input: { session: StoredSession<A>; meta: RequestMeta },
): Promise<AuthResult<IssuedSession<A>>> {
  const live = await core.confirmLiveSession(input.session);

  if (!live) return fail('session_expired', 'session_not_active');

  // High privilege, like revoking one device: a stolen session must not be
  // able to sign the owner out everywhere. Freshness is read from the live
  // copy, not from the object the caller passed in.
  const fresh = requireFreshAuth(core, settings, live);

  if (!fresh.ok) return fresh;

  const user = await core.users.findById(live.userId);

  if (!user) return fail('session_expired', 'user_missing');

  await core.revokeAllSessions(user.id, 'revoke-others');
  await core.tokens.revokeAll(user.id, SIGN_OUT_PURPOSES);

  return core.issueSession(user, {
    via: 'revoke-others',
    meta: input.meta,
    inherit: live,
    authenticatedAt: live.authenticatedAt,
  });
}

/** Signs out everywhere, this device included. */
export async function revokeAllSessions<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  input: { session: StoredSession<A>; meta: RequestMeta },
): Promise<{ cookie: CookieSpec }> {
  await core.revokeAllSessions(input.session.userId, 'revoke-all');
  await core.tokens.revokeAll(input.session.userId, SIGN_OUT_PURPOSES);

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
