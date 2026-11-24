// A048: getting a session past the second factor through another flow.
//
// The login asks for the factor, but other flows issue sessions too: sign-up
// with `autoLogin`, re-issues after a password change, a re-authentication or
// an email verification, a plugin's own sign-in. Any one of them that forgets
// the factor is a way around it, and an app that requires a factor of a user
// who has none must not hand that user a session at all.
//
// An app that runs a re-issue of its own (a password change, "sign out
// everywhere else") must get its user's session back, but only for a session
// that already proved the factor: never for a session it names without
// holding, nor for one that began before the factor existed.
//
// Stopped by: plugins/two-factor/hooks.ts (`beforeSessionCreate` refuses every session for a
//   user with a confirmed or required factor, unless it is the plugin's own, a re-issue of
//   a session the user already holds, or an app's re-issue of a live session that descends
//   from a proof of the factor: `provedFactor`), core/auth-core.ts (`issueSession` is the
//   only mint and always runs the hook; an app via's `inherit` must be live for the user, and
//   reaches the hooks as `reissueOf`), plugins/two-factor/challenge.ts (a required user
//   without a factor gets an enrollment challenge, not a session).
// Learn: Second factors (/auth/learn/second-factors/)
import { describe, expect, it } from 'vitest';

import {
  definePlugin,
  type AuthResult,
  type AuthUser,
  type IssuedSession,
  type PluginContext,
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

/** A plugin of the app's that re-issues the caller's session under its own via. */
function appReissue() {
  let context: PluginContext<AuthUser, Record<string, never>> | undefined;

  const plugin = definePlugin({
    id: 'appSessions',
    flows: (c) => {
      context = c as unknown as PluginContext<AuthUser, Record<string, never>>;

      return {};
    },
  });

  const ready = () => {
    if (!context) throw new Error('not built');

    return context;
  };

  return {
    plugin,
    reissue: (user: AuthUser, inherit?: Session) =>
      ready().issueSession(user, {
        via: 'app-password-change',
        meta: meta(),
        ...(inherit ? { inherit } : {}),
      }),
    confirm: (session: Session) => ready().confirmLiveSession(session),
    revokeAll: (userId: string) => ready().revokeAllSessions(userId, 'app-password-change'),
  };
}

const MINUTE = 60_000;

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

  it("lets an app's re-issue through only for a live session that proved the factor", async () => {
    const app = appReissue();
    const t = twoFactorApp({}, { plugins: [app.plugin] });
    const { session, secret, userId } = await t.enrolled();
    const user = await t.stores.users.findById(userId);

    if (!user) throw new Error('user');

    // The session that confirmed the factor holds the step-up from the confirmation.
    const fresh = await app.reissue(user, session);

    expect(fresh.ok).toBe(true);

    if (!fresh.ok) throw new Error(fresh.reason);

    // The new session began inside the enrollment window and holds no step-up of its own.
    expect(await app.reissue(user, fresh.value.session as Session)).toMatchObject({
      ok: false,
      code: 'second_factor_required',
      reason: 'second_factor_required:app-password-change',
    });

    // The confirming session began before the factor existed: once its step-up lapses, it is refused.
    t.clock.advance(11 * MINUTE);

    expect(await app.reissue(user, session)).toMatchObject({
      ok: false,
      code: 'second_factor_required',
    });

    // A session the challenge issued after the enrollment window passes for good.
    const proved = (await t.passed(secret)).session as Session;

    t.clock.advance(11 * MINUTE);

    expect((await app.reissue(user, proved)).ok).toBe(true);
  });

  it("refuses an app's re-issue that does not name a live session of that user", async () => {
    const app = appReissue();
    const t = twoFactorApp({}, { plugins: [app.plugin] });
    const { session, userId } = await t.enrolled();
    const other = await t.signedIn('grace@example.com');
    const user = await t.stores.users.findById(userId);

    if (!user) throw new Error('user');

    expect(await app.reissue(user)).toMatchObject({
      ok: false,
      code: 'second_factor_required',
      reason: 'second_factor_required:app-password-change',
    });

    const forged = { ...session, id: 'f'.repeat(64) };

    await t.auth.context.sessions.revoke(userId, [session.id]);

    for (const inherit of [session, other.session, forged])
      expect(await app.reissue(user, inherit)).toMatchObject({
        ok: false,
        code: 'session_expired',
        reason: 'reissue_without_session:app-password-change',
      });
  });

  it("lets an app's flow that ends every session re-issue the one it confirmed first, once", async () => {
    const app = appReissue();
    const t = twoFactorApp({}, { plugins: [app.plugin] });
    const { session, userId } = await t.enrolled();
    const user = await t.stores.users.findById(userId);

    if (!user) throw new Error('user');

    const live = await app.confirm(session);

    if (!live) throw new Error('live');

    await app.revokeAll(userId);

    expect((await app.reissue(user, live)).ok).toBe(true);

    // Spent by that issue, and no longer live in the store.
    expect(await app.reissue(user, live)).toMatchObject({
      ok: false,
      code: 'session_expired',
    });
  });

  it("refuses an app's re-issue of a dead session for a user without a factor too", async () => {
    const app = appReissue();
    const t = twoFactorApp({}, { plugins: [app.plugin] });
    const { session } = await t.signedIn();
    const user = await t.stores.users.findById(session.userId);

    if (!user) throw new Error('user');

    expect((await app.reissue(user, session)).ok).toBe(true);

    await t.auth.context.sessions.revoke(session.userId, [session.id]);

    expect(await app.reissue(user, session)).toMatchObject({
      ok: false,
      code: 'session_expired',
      reason: 'reissue_without_session:app-password-change',
    });
  });

  it("fences an app's re-issue at the epoch of the session it read, and carries the store's copy", async () => {
    const app = appReissue();
    const revokeDuring = { on: false };

    const t = twoFactorApp(
      {},
      {
        plugins: [app.plugin],
        hooks: {
          // A revoke-all that lands between the core's read and the mint.
          beforeSessionCreate: async ({ user, via }) => {
            if (revokeDuring.on && via === 'app-password-change') await app.revokeAll(user.id);
          },
        },
      },
    );

    const { session } = await t.signedIn();
    const user = await t.stores.users.findById(session.userId);

    if (!user) throw new Error('user');

    // A caller's object that claims more than the store holds.
    const claimed = { ...session, rememberMe: true, persistentCookie: true };
    const carried = await app.reissue(user, claimed);

    if (!carried.ok) throw new Error(carried.reason);

    expect(carried.value.session.rememberMe).toBe(false);
    expect(carried.value.session.persistentCookie).toBe(false);

    revokeDuring.on = true;

    expect(await app.reissue(user, carried.value.session as Session)).toMatchObject({
      ok: false,
      reason: 'epoch_fence',
    });
  });
});
