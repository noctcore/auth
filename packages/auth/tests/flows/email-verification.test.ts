import { describe, expect, it } from 'vitest';
import { meta, PASSWORD, setup } from './setup';

describe('email verification by code (default)', () => {
  it('verifies the address, ends every other session and re-issues the current one', async () => {
    const env = setup();
    const { token, session } = await env.signedInUser();
    const other = await env.auth.login({
      email: 'ada@example.com',
      password: PASSWORD,
      meta: meta('198.51.100.2'),
    });
    const code = env.mailer.last('verify-email')?.code ?? '';

    const result = await env.auth.verifyEmailCode({ session, code, meta: meta() });
    if (!result.ok || !result.value.session) throw new Error('expected a re-issued session');
    expect((await env.stores.users.findById(session.userId))?.emailVerified).toBe(true);
    expect(await env.sessionOf(token)).toBeNull();
    if (other.ok && other.value.kind === 'session')
      expect(await env.sessionOf(other.value.session.token)).toBeNull();
    expect(await env.sessionOf(result.value.session.token)).not.toBeNull();
    expect(result.value.session.session.authenticatedAt).toBe(session.authenticatedAt);
  });

  it('accepts the code only from the account it was sent to', async () => {
    const env = setup();
    const ada = await env.signedInUser('ada@example.com');
    const adaCode = env.mailer.last('verify-email')?.code ?? '';
    const eve = await env.signedInUser('eve@example.com', '198.51.100.9');
    const stolen = await env.auth.verifyEmailCode({
      session: eve.session,
      code: adaCode,
      meta: meta(),
    });
    expect(!stolen.ok && stolen.code).toBe('invalid_token');
    expect((await env.stores.users.findById(ada.session.userId))?.emailVerified).toBe(false);
  });

  it('allows 5 wrong codes, then voids the code', async () => {
    const env = setup();
    const { session } = await env.signedInUser();
    const code = env.mailer.last('verify-email')?.code ?? '';
    const wrong = code === '00000000' ? '11111111' : '00000000';
    for (let i = 0; i < 5; i++)
      await env.auth.verifyEmailCode({ session, code: wrong, meta: meta() });
    const late = await env.auth.verifyEmailCode({ session, code, meta: meta() });
    expect(!late.ok && late.code).toBe('invalid_token');
  });

  it('refuses a code mailed to an address the account no longer has', async () => {
    const env = setup();
    const { session } = await env.signedInUser();
    const code = env.mailer.last('verify-email')?.code ?? '';
    await env.stores.users.setEmail(session.userId, 'new@example.com' as never);
    const result = await env.auth.verifyEmailCode({ session, code, meta: meta() });
    expect(!result.ok && result.reason).toBe('verification_address_changed');
  });

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
});

describe('email verification by link', () => {
  it('verifies only from a signed-in session of the same account, and leaves the link unspent otherwise', async () => {
    const env = setup({ emailVerification: { kind: 'link' } });
    const { token: cookie, session } = await env.signedInUser();
    const eve = await env.signedInUser('eve@example.com', '198.51.100.9');
    const url = env.mailer.sent
      .filter((m) => m.type === 'verify-email' && m.to === 'ada@example.com')
      .at(-1);
    const token = (url?.type === 'verify-email' ? (url.url ?? '') : '').split('#')[1] ?? '';

    const anonymous = await env.auth.verifyEmailLink({ token, session: null, meta: meta() });
    expect(!anonymous.ok && anonymous.reason).toBe('verification_session_required');
    const wrongAccount = await env.auth.verifyEmailLink({
      token,
      session: eve.session,
      meta: meta(),
    });
    expect(!wrongAccount.ok && wrongAccount.reason).toBe('verification_session_required');
    expect((await env.stores.users.findById(session.userId))?.emailVerified).toBe(false);

    const result = await env.auth.verifyEmailLink({ token, session, meta: meta() });
    if (!result.ok || !result.value.session) throw new Error('expected a re-issued session');
    expect((await env.stores.users.findById(session.userId))?.emailVerified).toBe(true);
    expect(await env.sessionOf(cookie)).toBeNull();
    const replay = await env.auth.verifyEmailLink({
      token,
      session: result.value.session.session,
      meta: meta(),
    });
    expect(!replay.ok && replay.code).toBe('invalid_token');
  });
});
