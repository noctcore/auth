// A048: getting a session past the second factor through another flow.
//
// The login asks for the factor, but other flows issue sessions too: sign-up
// with `autoLogin`, re-issues after a password change, a re-authentication or
// an email verification, a plugin's own sign-in. Any one of them that forgets
// the factor is a way around it, and an app that requires a factor of a user
// who has none must not hand that user a session at all.
//
// Stopped by: plugins/two-factor/hooks.ts (`beforeSessionCreate` refuses every session for a
//   user with a confirmed or required factor, unless it is the plugin's own or a re-issue of
//   a session the user already holds), core/auth-core.ts (`issueSession` is the only mint
//   and always runs the hook), plugins/two-factor/challenge.ts (a required user without a
//   factor gets an enrollment challenge, not a session).
// Learn: Second factors (/auth/learn/second-factors/)
import { describe, expect, it } from 'vitest';

import {
  definePlugin,
  type AuthResult,
  type AuthUser,
  type IssuedSession,
  type StoredSession,
} from '../../src';
import { EMAIL, meta, NEW_PASSWORD, PASSWORD, twoFactorApp } from '../two-factor/setup';

type Session = StoredSession<Record<string, never>>;

/** A plugin with a sign-in of its own (a magic link, say) that issues sessions through the seam. */
function magicLink() {
  let issue: ((user: AuthUser) => Promise<AuthResult<IssuedSession<unknown>>>) | undefined;

  const plugin = definePlugin({
    id: 'magicLink',
    flows: (context) => {
      issue = (user) => context.issueSession(user, { via: 'magic-link', meta: meta() });

      return {};
    },
  });

  return { plugin, signIn: (user: AuthUser) => issue?.(user) };
}

describe('A048: getting a session past the second factor through another flow', () => {
  it('gives a required user without a factor an enrollment challenge, never a session', async () => {
    const t = twoFactorApp({ required: () => true });

    await t.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });

    const login = await t.auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    expect(login.ok && login.value.kind === 'challenge' && login.value.methods).toEqual(['enroll']);
  });

  it('refuses the autoLogin session of a sign-up the app requires a factor of', async () => {
    const t = twoFactorApp(
      { required: () => true },
      { registration: { revealExisting: true, autoLogin: true } },
    );

    const registered = await t.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });

    expect(registered).toMatchObject({
      ok: false,
      code: 'second_factor_required',
      reason: 'second_factor_required:register',
    });
  });

  it('refuses a session another plugin issues for a user with a factor', async () => {
    const link = magicLink();
    const t = twoFactorApp({}, { plugins: [link.plugin] });
    const { userId } = await t.enrolled();
    const user = await t.stores.users.findById(userId);

    if (!user) throw new Error('user');

    expect(await link.signIn(user)).toMatchObject({
      ok: false,
      code: 'second_factor_required',
      reason: 'second_factor_required:magic-link',
    });

    // The same plugin works for a user without a factor.
    const plain = await t.signedIn('grace@example.com');
    const grace = await t.stores.users.findById(plain.session.userId);

    expect((await link.signIn(grace ?? user))?.ok).toBe(true);
  });

  it('refuses a password-login session for a user with a factor, whatever skipped the challenge', async () => {
    const t = twoFactorApp();
    const { userId } = await t.enrolled();
    const user = await t.stores.users.findById(userId);

    if (!user) throw new Error('user');

    const issued = await t.auth.context.issueSession(user, { via: 'password', meta: meta() });

    expect(issued).toMatchObject({
      ok: false,
      code: 'second_factor_required',
      reason: 'second_factor_required:password',
    });
  });

  it('refuses a session for a required user through any flow but the challenge', async () => {
    const t = twoFactorApp({ required: ({ user }) => user.email === EMAIL });

    await t.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });

    const user = await t.stores.users.findCredentialByEmail(EMAIL as never);

    for (const via of ['password', 'register', 'magic-link', 'oauth']) {
      const issued = await t.auth.context.issueSession(
        { id: user?.id ?? '', email: EMAIL, emailVerified: false },
        { via, meta: meta() },
      );

      expect(issued).toMatchObject({ ok: false, code: 'second_factor_required' });
    }
  });

  it('lets the re-issues of a session the user already holds through', async () => {
    const t = twoFactorApp({}, { emailVerification: { kind: 'code' } });
    const { session, secret } = await t.enrolled();
    const reauth = await t.auth.reauthenticate({ session, password: PASSWORD, meta: meta() });

    if (!reauth.ok) throw new Error(reauth.reason);

    const others = await t.auth.sessions.revokeOthers({
      session: reauth.value.session,
      meta: meta(),
    });

    if (!others.ok) throw new Error(others.reason);

    const changed = await t.auth.changePassword({
      session: others.value.session,
      currentPassword: PASSWORD,
      newPassword: NEW_PASSWORD,
      secondFactor: t.codeFor(secret),
      meta: meta(),
    });

    expect(changed.ok).toBe(true);
  });

  it('applies to a sign-up whose user enrolled later: each new login is challenged', async () => {
    const t = twoFactorApp({}, { registration: { revealExisting: true, autoLogin: true } });
    const registered = await t.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });

    if (!registered.ok || !registered.value.session) throw new Error('autoLogin');

    const session = registered.value.session.session;
    const started = await t.auth.twoFactor.enroll({ session, meta: meta() });

    if (!started.ok) throw new Error(started.reason);

    await t.auth.twoFactor.confirmEnrollment({
      session,
      code: t.codeFor(started.value.secret),
      meta: meta(),
    });

    const login = await t.auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    expect(login.ok && login.value.kind).toBe('challenge');
  });

  it('refuses a re-issue label without a live session of that user, read by the core', async () => {
    const t = twoFactorApp();
    const { userId, session } = await t.enrolled();
    const other = await t.signedIn('grace@example.com');
    const user = await t.stores.users.findById(userId);

    if (!user) throw new Error('user');

    // `auth.context` is the core at runtime; `confirmLiveSession` is not on the plugin type.
    const core = t.auth.context as typeof t.auth.context & {
      confirmLiveSession: (s: Session) => Promise<Session | null>;
    };

    const [listed] = await t.auth.context.sessions.listActive(userId);
    const forged = { ...session, id: 'f'.repeat(64) };
    const vias = ['password-change', 'reauthenticate', 'revoke-others', 'email-verified'];

    for (const via of vias) {
      // No session, another user's, one straight from listActive, a forged one,
      // and the caller's own object that the core never confirmed.
      for (const inherit of [undefined, other.session, listed, forged, session]) {
        const issued = await core.issueSession(user, {
          via,
          meta: meta(),
          ...(inherit ? { inherit } : {}),
        });

        expect(issued).toMatchObject({ ok: false, reason: `reissue_without_session:${via}` });
      }
    }

    // A forged session never confirms, and another user's session never confirms for this one.
    expect(await core.confirmLiveSession(forged)).toBeNull();
    expect(await core.confirmLiveSession({ ...other.session, userId })).toBeNull();

    // Confirmed live, it opens one re-issue, once.
    const live = await core.confirmLiveSession(session);

    if (!live) throw new Error('live');

    const once = await core.issueSession(user, {
      via: 'reauthenticate',
      meta: meta(),
      inherit: live,
    });

    const twice = await core.issueSession(user, {
      via: 'reauthenticate',
      meta: meta(),
      inherit: live,
    });

    expect(once.ok).toBe(true);
    expect(twice).toMatchObject({ ok: false, reason: 'reissue_without_session:reauthenticate' });
  });

  it('refuses the re-issue flows on a revoked or expired session, before revoking anything', async () => {
    const t = twoFactorApp();
    const { session, secret } = await t.enrolled();
    const spare = (await t.passed(secret)).session;

    // Revoked: the flows refuse and the user's other session stays.
    await t.auth.context.sessions.revoke(session.userId, [session.id]);

    const reauth = await t.auth.reauthenticate({ session, password: PASSWORD, meta: meta() });
    const others = await t.auth.sessions.revokeOthers({ session, meta: meta() });

    const changed = await t.auth.changePassword({
      session,
      currentPassword: PASSWORD,
      newPassword: NEW_PASSWORD,
      secondFactor: t.codeFor(secret),
      meta: meta(),
    });

    for (const result of [reauth, others, changed])
      expect(result).toMatchObject({ ok: false, reason: 'session_not_active' });

    const stillThere = await t.auth.context.sessions.listActive(session.userId);

    expect(stillThere.map((s) => s.id)).toContain(spare.id);

    // Expired: past the absolute lifetime the same flows refuse.
    t.clock.advance(400 * 24 * 60 * 60_000);

    const late = await t.auth.reauthenticate({
      session: spare,
      password: PASSWORD,
      meta: meta(),
    });

    expect(late).toMatchObject({ ok: false, reason: 'session_not_active' });
  });
});
