import { describe, expect, it } from 'vitest';
import { meta, setup } from './setup';

describe('email verification by code (default)', () => {
  it('expires the code after 15 minutes', async () => {
    const env = setup();
    const { session } = await env.signedInUser();
    const code = env.mailer.last('verify-email')?.code ?? '';

    env.clock.advance(15 * 60_000);
    const result = await env.auth.verifyEmailCode({ session, code, meta: meta() });

    expect(!result.ok && result.reason).toBe('verification_expired');
  });

  it('resends to unverified accounts only, within the per-user mail limit', async () => {
    const env = setup();
    const { session } = await env.signedInUser();
    const sends = [];

    for (let i = 0; i < 4; i++)
      sends.push(await env.auth.requestEmailVerification({ session, meta: meta() }));

    expect(sends.map((s) => s.ok)).toEqual([true, true, true, false]);
    const code = env.mailer.last('verify-email')?.code ?? '';
    const verified = await env.auth.verifyEmailCode({ session, code, meta: meta() });

    if (!verified.ok || !verified.value.session) throw new Error('verify failed');

    env.clock.advance(3_600_000);

    const after = await env.auth.requestEmailVerification({
      session: verified.value.session.session,
      meta: meta(),
    });

    expect(after).toEqual({ ok: true, value: { sent: false } });
  });

  it('verifies the address but re-issues no session for one that was revoked meanwhile', async () => {
    const env = setup();
    const { session } = await env.signedInUser();
    const code = env.mailer.last('verify-email')?.code ?? '';

    await env.auth.context.sessions.revoke(session.userId, [session.id]);

    const result = await env.auth.verifyEmailCode({ session, code, meta: meta() });

    expect(result).toEqual({ ok: true, value: { session: null } });
    expect((await env.stores.users.findById(session.userId))?.emailVerified).toBe(true);
  });
});

describe('email verification by link without a session (linkWithoutSession)', () => {
  const sessionless = () =>
    setup({ emailVerification: { kind: 'link', linkWithoutSession: true } });

  const linkTo = (app: ReturnType<typeof setup>, email = 'ada@example.com') => {
    const mail = app.mailer.sent.filter((m) => m.type === 'verify-email' && m.to === email).at(-1);

    return (mail?.type === 'verify-email' ? (mail.url ?? '') : '').split('#')[1] ?? '';
  };

  it('refuses a link opened without a session by default, and leaves it unspent', async () => {
    const app = setup({ emailVerification: { kind: 'link' } });
    const { session } = await app.signedInUser();
    const token = linkTo(app);

    const anonymous = await app.auth.verifyEmailLink({ token, session: null, meta: meta() });

    expect(!anonymous.ok && anonymous.reason).toBe('verification_session_required');
    expect((await app.stores.users.findById(session.userId))?.emailVerified).toBe(false);

    const signedIn = await app.auth.verifyEmailLink({ token, session, meta: meta() });

    expect(signedIn.ok).toBe(true);
  });

  it('verifies without a session, signs nobody in and ends every session', async () => {
    const app = sessionless();
    const { token: cookie, session } = await app.signedInUser();

    const result = await app.auth.verifyEmailLink({
      token: linkTo(app),
      session: null,
      meta: meta('198.51.100.4'),
    });

    expect(result).toEqual({ ok: true, value: { session: null } });
    expect((await app.stores.users.findById(session.userId))?.emailVerified).toBe(true);
    expect(await app.sessionOf(cookie)).toBeNull();
    expect(app.audit.types()).toContain('email.verified');
  });

  it('still re-issues the session when opened signed in as the same account', async () => {
    const app = sessionless();
    const { session } = await app.signedInUser();

    const result = await app.auth.verifyEmailLink({ token: linkTo(app), session, meta: meta() });

    if (!result.ok || !result.value.session) throw new Error('expected a re-issued session');

    expect(result.value.session.session.userId).toBe(session.userId);
  });

  it("refuses the link inside another account's session, and leaves it unspent", async () => {
    const app = sessionless();
    const ada = await app.signedInUser();
    const token = linkTo(app);
    const eve = await app.signedInUser('eve@example.com', '198.51.100.9');

    const wrong = await app.auth.verifyEmailLink({ token, session: eve.session, meta: meta() });

    expect(!wrong.ok && wrong.reason).toBe('verification_session_required');
    expect((await app.stores.users.findById(ada.session.userId))?.emailVerified).toBe(false);
    expect(await app.sessionOf(eve.token)).not.toBeNull();

    const later = await app.auth.verifyEmailLink({ token, session: null, meta: meta() });

    expect(later.ok).toBe(true);
  });

  it('refuses a reused link', async () => {
    const app = sessionless();

    await app.signedInUser();
    const token = linkTo(app);

    const first = await app.auth.verifyEmailLink({ token, session: null, meta: meta() });
    const replay = await app.auth.verifyEmailLink({ token, session: null, meta: meta() });

    expect(first.ok).toBe(true);
    expect(!replay.ok && replay.code).toBe('invalid_token');
  });

  it('refuses an expired link', async () => {
    const app = sessionless();
    const { session } = await app.signedInUser();
    const token = linkTo(app);

    app.clock.advance(24 * 3_600_000);
    const result = await app.auth.verifyEmailLink({ token, session: null, meta: meta() });

    expect(!result.ok && result.reason).toBe('verification_expired');
    expect((await app.stores.users.findById(session.userId))?.emailVerified).toBe(false);
  });

  it('refuses a link mailed to an address the account no longer has', async () => {
    const app = sessionless();
    const { session } = await app.signedInUser();
    const token = linkTo(app);

    await app.stores.users.setEmail(session.userId, 'new@example.com' as never);
    const result = await app.auth.verifyEmailLink({ token, session: null, meta: meta() });

    expect(!result.ok && result.reason).toBe('verification_address_changed');
    expect((await app.stores.users.findById(session.userId))?.emailVerified).toBe(false);
  });

  it('verifies once when two sessionless clicks race', async () => {
    const app = sessionless();
    const { session } = await app.signedInUser();
    const token = linkTo(app);

    const results = await Promise.all([
      app.auth.verifyEmailLink({ token, session: null, meta: meta() }),
      app.auth.verifyEmailLink({ token, session: null, meta: meta('198.51.100.5') }),
    ]);

    expect(results.filter((r) => r.ok)).toHaveLength(1);
    expect(results.find((r) => !r.ok)).toMatchObject({ ok: false, code: 'invalid_token' });
    expect(app.audit.types().filter((t) => t === 'email.verified')).toHaveLength(1);
    expect((await app.stores.users.findById(session.userId))?.emailVerified).toBe(true);
  });

  it.each(['false', 'true', 'yes', 1])('is refused at startup when set to %j', (value) => {
    expect(() =>
      setup({ emailVerification: { kind: 'link', linkWithoutSession: value as never } }),
    ).toThrow('emailVerification.linkWithoutSession must be true or false');
  });

  it('is refused at startup for code verification', () => {
    expect(() => setup({ emailVerification: { linkWithoutSession: true } })).toThrow(
      'emailVerification.linkWithoutSession needs kind: link',
    );
  });
});
