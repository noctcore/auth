import { describe, expect, it } from 'vitest';

import { changed, requestCode, tokenOf } from './email-change-support';
import { meta, NEW_PASSWORD, PASSWORD, setup } from './setup';

const NEW = 'grace@example.com';

describe('requestEmailChange', () => {
  it('mails a code to the new address and leaves the login on the old one', async () => {
    const t = setup();
    const { session } = await t.signedInUser();

    const requested = await t.auth.requestEmailChange({
      session,
      newEmail: ' Grace@Example.com ',
      meta: meta(),
    });

    expect(requested).toEqual({ ok: true, value: { expiresAt: t.clock.now() + 15 * 60_000 } });

    const mail = t.mailer.last('email-change-confirm');

    expect(mail).toMatchObject({ to: NEW, userId: session.userId });
    expect(mail?.code).toMatch(/^\d{8}$/u);
    expect(mail?.url).toBeUndefined();
    expect((await t.stores.users.findById(session.userId))?.email).toBe('ada@example.com');

    expect(t.audit.events.at(-1)).toMatchObject({
      type: 'email.change_requested',
      userId: session.userId,
      data: { kind: 'code' },
    });
  });

  it('refuses a session that is no longer live', async () => {
    const t = setup();
    const { session, token } = await t.signedInUser();

    await t.auth.logout({ token, meta: meta() });

    expect(await t.auth.requestEmailChange({ session, newEmail: NEW, meta: meta() })).toMatchObject(
      {
        ok: false,
        code: 'session_expired',
        reason: 'session_not_active',
      },
    );
  });

  it('refuses a stale credential proof, an invalid address and the current address', async () => {
    const t = setup();
    const { session } = await t.signedInUser();

    expect(
      await t.auth.requestEmailChange({ session, newEmail: 'not an address', meta: meta() }),
    ).toMatchObject({ ok: false, code: 'invalid_email', reason: 'invalid_email' });

    expect(
      await t.auth.requestEmailChange({ session, newEmail: 'ADA@example.com', meta: meta() }),
    ).toMatchObject({ ok: false, code: 'invalid_email', reason: 'email_unchanged' });

    t.clock.advance(10 * 60_000 + 1);

    expect(await t.auth.requestEmailChange({ session, newEmail: NEW, meta: meta() })).toMatchObject(
      {
        ok: false,
        code: 'fresh_auth_required',
      },
    );

    expect(
      t.audit.events.filter((e) => e.type === 'email.change_failed').map((e) => e.reason),
    ).toEqual(['invalid_email', 'email_unchanged', 'stale_authentication']);
  });

  it('answers a missing user as an ended session', async () => {
    const t = setup();
    const { session } = await t.signedInUser();

    await t.stores.users.softDelete(session.userId);

    expect(await t.auth.requestEmailChange({ session, newEmail: NEW, meta: meta() })).toMatchObject(
      {
        ok: false,
        code: 'session_expired',
        reason: 'user_missing',
      },
    );
  });

  it('limits requests per account and per new address', async () => {
    const t = setup();
    const { session } = await t.signedInUser();

    for (let i = 0; i < 3; i++)
      expect(
        (await t.auth.requestEmailChange({ session, newEmail: `n${i}@example.com`, meta: meta() }))
          .ok,
      ).toBe(true);

    expect(
      await t.auth.requestEmailChange({ session, newEmail: 'n4@example.com', meta: meta() }),
    ).toMatchObject({
      ok: false,
      code: 'rate_limited',
      reason: 'rate_limited:email-change-request',
    });

    const u = setup();
    const target = 'shared@example.com';

    for (let i = 0; i < 3; i++) {
      const other = await u.signedInUser(`user${i}@example.com`, `198.51.100.${i + 1}`);

      expect(
        (
          await u.auth.requestEmailChange({
            session: other.session,
            newEmail: target,
            meta: meta(),
          })
        ).ok,
      ).toBe(true);
    }

    const last = await u.signedInUser('user9@example.com', '198.51.100.9');

    expect(
      await u.auth.requestEmailChange({ session: last.session, newEmail: target, meta: meta() }),
    ).toMatchObject({
      ok: false,
      code: 'rate_limited',
      reason: 'rate_limited:email-change-address',
    });
  });

  it('runs the beforeEmailChange hooks with the normalised address and honours a refusal', async () => {
    const seen: string[] = [];

    const t = setup({
      hooks: {
        beforeEmailChange: ({ newEmail, secondFactor }) => {
          seen.push(`${newEmail}:${secondFactor ?? '-'}`);

          return { refuse: true, code: 'forbidden', reason: 'policy' };
        },
      },
    });

    const { session } = await t.signedInUser();

    expect(
      await t.auth.requestEmailChange({
        session,
        newEmail: 'GRACE@example.com',
        secondFactor: '123456',
        meta: meta(),
      }),
    ).toMatchObject({ ok: false, code: 'forbidden', reason: 'policy' });

    expect(seen).toEqual([`${NEW}:123456`]);
    expect(t.mailer.last('email-change-confirm')).toBeUndefined();
  });

  it('mails a link in link mode', async () => {
    const t = setup({ emailChange: { kind: 'link' } });
    const { session } = await t.signedInUser();

    const requested = await t.auth.requestEmailChange({ session, newEmail: NEW, meta: meta() });

    expect(requested).toEqual({ ok: true, value: { expiresAt: t.clock.now() + 60 * 60_000 } });

    expect(t.mailer.last('email-change-confirm')?.url).toMatch(
      /^https:\/\/app\.example\/email\/confirm#[0-9a-f]{64}$/u,
    );
  });
});

describe('confirmEmailChangeCode', () => {
  it('moves the account, verifies the new address, ends every other session and mails the old one', async () => {
    const t = setup();
    const { session } = await t.signedInUser();

    const other = await t.auth.login({
      email: 'ada@example.com',
      password: PASSWORD,
      meta: meta(),
    });

    if (!other.ok || other.value.kind !== 'session') throw new Error('login failed');

    const code = await requestCode(t, session, NEW);
    const confirmed = await t.auth.confirmEmailChangeCode({ session, code, meta: meta() });

    if (!confirmed.ok || !confirmed.value.session) throw new Error('confirm failed');

    expect(confirmed.value.session.session.id).not.toBe(session.id);
    expect(confirmed.value.session.session.authenticatedAt).toBe(session.authenticatedAt);

    expect(await t.stores.users.findById(session.userId)).toMatchObject({
      email: NEW,
      emailVerified: true,
    });

    expect(await t.sessionOf(other.value.session.token)).toBeNull();
    expect(await t.sessionOf(confirmed.value.session.token)).not.toBeNull();

    const notice = t.mailer.last('email-changed');

    expect(notice).toMatchObject({ to: 'ada@example.com', newEmail: NEW, userId: session.userId });
    expect(notice?.revertUrl).toMatch(/^https:\/\/app\.example\/email\/revert#[0-9a-f]{64}$/u);
    expect(notice?.revertExpiresAt?.getTime()).toBe(t.clock.now() + 7 * 24 * 60 * 60_000);
    expect(t.audit.types()).toContain('email.changed');

    // The new address is now the login; the old one is not.
    const login = await t.auth.login({
      email: NEW,
      password: PASSWORD,
      meta: meta('198.51.100.1'),
    });

    expect(login.ok).toBe(true);

    expect(
      (
        await t.auth.login({
          email: 'ada@example.com',
          password: PASSWORD,
          meta: meta('198.51.100.2'),
        })
      ).ok,
    ).toBe(false);
  });

  it('voids reset and verification tokens mailed to the old address', async () => {
    const t = setup();
    const { session } = await t.signedInUser();

    await t.auth.requestPasswordReset({ email: 'ada@example.com', meta: meta() });
    await new Promise((resolve) => setTimeout(resolve, 0));

    const reset = tokenOf(t.mailer.last('password-reset')?.url);

    expect(reset).not.toBe('');

    await changed(t, session, NEW);

    expect(
      await t.auth.resetPassword({ token: reset, password: NEW_PASSWORD, meta: meta() }),
    ).toMatchObject({ ok: false, code: 'invalid_token' });
  });

  it('refuses a wrong code and counts it', async () => {
    const t = setup();
    const { session } = await t.signedInUser();
    const code = await requestCode(t, session, NEW);
    const wrong = code === '00000000' ? '11111111' : '00000000';

    expect(
      await t.auth.confirmEmailChangeCode({ session, code: wrong, meta: meta() }),
    ).toMatchObject({
      ok: false,
      code: 'invalid_token',
      reason: 'email_change_mismatch',
    });

    expect(t.audit.events.at(-1)).toMatchObject({
      type: 'email.change_failed',
      userId: session.userId,
    });
  });

  it('answers an unknown code without naming an account', async () => {
    const t = setup();
    const { session } = await t.signedInUser();

    expect(
      await t.auth.confirmEmailChangeCode({ session, code: '12345678', meta: meta() }),
    ).toMatchObject({
      ok: false,
      code: 'invalid_token',
      reason: 'email_change_unknown',
    });

    expect(t.audit.events.at(-1)).toMatchObject({ type: 'email.change_failed' });
    expect(t.audit.events.at(-1)?.userId).toBeUndefined();
  });

  it('confirms without a session to re-issue when the caller session ended meanwhile', async () => {
    const t = setup();
    const { session, token } = await t.signedInUser();
    const code = await requestCode(t, session, NEW);

    await t.auth.logout({ token, meta: meta() });

    expect(await t.auth.confirmEmailChangeCode({ session, code, meta: meta() })).toEqual({
      ok: true,
      value: { session: null },
    });

    expect((await t.stores.users.findById(session.userId))?.email).toBe(NEW);
  });

  it('refuses when the new address was taken between the request and the confirmation', async () => {
    const t = setup();
    const { session } = await t.signedInUser();
    const code = await requestCode(t, session, NEW);

    await t.auth.register({ email: NEW, password: PASSWORD, meta: meta() });

    expect(await t.auth.confirmEmailChangeCode({ session, code, meta: meta() })).toMatchObject({
      ok: false,
      code: 'email_in_use',
      reason: 'email_change_taken',
    });

    expect((await t.stores.users.findById(session.userId))?.email).toBe('ada@example.com');
  });

  it('refuses when the store loses the compare-and-set', async () => {
    const t = setup();
    const { session } = await t.signedInUser();
    const code = await requestCode(t, session, NEW);
    const users = t.stores.users;

    users.changeEmail = async () => 'stale';

    expect(await t.auth.confirmEmailChangeCode({ session, code, meta: meta() })).toMatchObject({
      ok: false,
      code: 'invalid_token',
      reason: 'email_change_stale',
    });
  });

  it('refuses a proof whose user is gone or whose stored addresses are unreadable', async () => {
    const t = setup();
    const { session } = await t.signedInUser();
    const code = await requestCode(t, session, NEW);

    await t.stores.users.softDelete(session.userId);

    expect(await t.auth.confirmEmailChangeCode({ session, code, meta: meta() })).toMatchObject({
      ok: false,
      reason: 'email_change_address_changed',
    });

    const u = setup();
    const signed = await u.signedInUser();

    await u.stores.tokens.put({
      purpose: 'email-change',
      userId: signed.session.userId,
      hash: 'x',
      expiresAt: u.clock.now() + 60_000,
      attempts: 0,
      data: {},
    });

    const forged = await u.auth.context.tokens.issueLink(
      'email-change',
      signed.session.userId,
      60_000,
      {},
    );

    expect(
      await u.auth.confirmEmailChangeLink({
        token: forged.token,
        session: signed.session,
        meta: meta(),
      }),
    ).toMatchObject({ ok: false, reason: 'email_change_address_changed' });

    const half = await u.auth.context.tokens.issueLink(
      'email-change',
      signed.session.userId,
      60_000,
      {
        email: NEW,
      },
    );

    expect(
      await u.auth.confirmEmailChangeLink({
        token: half.token,
        session: signed.session,
        meta: meta(),
      }),
    ).toMatchObject({ ok: false, reason: 'email_change_address_changed' });
  });

  it('is rate limited per IP', async () => {
    const t = setup({ throttle: { doors: { 'email-change': { limit: 1, window: '1m' } } } });
    const { session } = await t.signedInUser();

    await t.auth.confirmEmailChangeCode({ session, code: '12345678', meta: meta() });

    expect(
      await t.auth.confirmEmailChangeCode({ session, code: '12345678', meta: meta() }),
    ).toMatchObject({
      ok: false,
      code: 'rate_limited',
    });

    expect(
      await t.auth.confirmEmailChangeLink({ token: 'x', session, meta: meta() }),
    ).toMatchObject({ ok: false, code: 'rate_limited' });
  });

  it('passes on a re-issue refusal from the core', async () => {
    const t = setup({
      hooks: {
        beforeSessionCreate: ({ via }) =>
          via === 'email-changed' ? { refuse: true, code: 'forbidden', reason: 'no' } : undefined,
      },
    });

    const { session } = await t.signedInUser();
    const code = await requestCode(t, session, NEW);

    expect(await t.auth.confirmEmailChangeCode({ session, code, meta: meta() })).toMatchObject({
      ok: false,
      code: 'forbidden',
    });
  });
});

describe('confirmEmailChangeLink', () => {
  it('confirms in a signed-in session of the same account', async () => {
    const t = setup({ emailChange: { kind: 'link' } });
    const { session } = await t.signedInUser();

    await t.auth.requestEmailChange({ session, newEmail: NEW, meta: meta() });

    const token = tokenOf(t.mailer.last('email-change-confirm')?.url);
    const confirmed = await t.auth.confirmEmailChangeLink({ token, session, meta: meta() });

    expect(confirmed.ok && confirmed.value.session?.session.userId).toBe(session.userId);
    expect((await t.stores.users.findById(session.userId))?.email).toBe(NEW);
  });

  it('refuses without the account session and leaves the link unspent', async () => {
    const t = setup({ emailChange: { kind: 'link' } });
    const { session } = await t.signedInUser();
    const stranger = await t.signedInUser('eve@example.com', '198.51.100.20');

    await t.auth.requestEmailChange({ session, newEmail: NEW, meta: meta() });

    const token = tokenOf(t.mailer.last('email-change-confirm')?.url);

    for (const other of [null, stranger.session]) {
      expect(
        await t.auth.confirmEmailChangeLink({ token, session: other, meta: meta() }),
      ).toMatchObject({
        ok: false,
        code: 'session_expired',
        reason: 'email_change_session_required',
      });
    }

    expect((await t.auth.confirmEmailChangeLink({ token, session, meta: meta() })).ok).toBe(true);

    expect(await t.auth.confirmEmailChangeLink({ token, session, meta: meta() })).toMatchObject({
      ok: false,
      reason: 'email_change_unknown',
    });
  });
});

describe('revertEmailChange', () => {
  it('restores the old address, removes the password, ends every session and flags the account', async () => {
    const t = setup();
    const { session } = await t.signedInUser();
    const after = await changed(t, session, NEW);

    expect(await t.auth.revertEmailChange({ token: after.revert, meta: meta() })).toEqual({
      ok: true,
      value: undefined,
    });

    expect(await t.stores.users.findCredentialById(session.userId)).toMatchObject({
      email: 'ada@example.com',
      emailVerified: true,
      passwordHash: null,
    });

    expect(await t.stores.sessions.listByUser(session.userId)).toEqual([]);

    expect(t.audit.events.find((e) => e.type === 'email.change_reverted')).toMatchObject({
      userId: session.userId,
      data: { review: true, passwordCleared: true },
    });

    expect(t.mailer.last('email-change-reverted')).toMatchObject({ to: 'ada@example.com' });

    // The next sign-in needs a reset, which goes to the restored address.
    expect(
      (
        await t.auth.login({
          email: 'ada@example.com',
          password: PASSWORD,
          meta: meta('198.51.100.3'),
        })
      ).ok,
    ).toBe(false);
  });

  it('blocks the lost address for the account, until the block lapses', async () => {
    const t = setup();
    const { session } = await t.signedInUser();
    const after = await changed(t, session, NEW);

    await t.auth.revertEmailChange({ token: after.revert, meta: meta() });

    await t.stores.users.setPasswordHash(
      session.userId,
      await t.auth.context.hasher.hash(PASSWORD),
    );

    const login = await t.auth.login({
      email: 'ada@example.com',
      password: PASSWORD,
      meta: meta('198.51.100.4'),
    });

    if (!login.ok || login.value.kind !== 'session') throw new Error('login failed');

    const fresh = login.value.session.session;

    expect(
      await t.auth.requestEmailChange({ session: fresh, newEmail: NEW, meta: meta() }),
    ).toMatchObject({
      ok: false,
      code: 'forbidden',
      reason: 'email_change_blocked',
    });

    expect(
      (
        await t.auth.requestEmailChange({
          session: fresh,
          newEmail: 'other@example.com',
          meta: meta(),
        })
      ).ok,
    ).toBe(true);
  });

  it('refuses an unknown, malformed or expired link', async () => {
    const t = setup();
    const { session } = await t.signedInUser();
    const after = await changed(t, session, NEW);

    expect(await t.auth.revertEmailChange({ token: 'nope', meta: meta() })).toMatchObject({
      ok: false,
      code: 'invalid_token',
      reason: 'email_revert_unknown',
    });

    t.clock.advance(7 * 24 * 60 * 60_000 + 1);

    expect(await t.auth.revertEmailChange({ token: after.revert, meta: meta() })).toMatchObject({
      ok: false,
      reason: 'email_revert_expired',
    });

    expect(t.audit.events.at(-1)).toMatchObject({
      type: 'email.change_revert_failed',
      userId: session.userId,
      data: { review: true },
    });

    expect((await t.stores.users.findById(session.userId))?.email).toBe(NEW);
  });

  it('refuses when the old address now belongs to another account', async () => {
    const t = setup();
    const { session } = await t.signedInUser();
    const after = await changed(t, session, NEW);

    await t.auth.register({ email: 'ada@example.com', password: PASSWORD, meta: meta() });

    expect(await t.auth.revertEmailChange({ token: after.revert, meta: meta() })).toMatchObject({
      ok: false,
      code: 'email_in_use',
      reason: 'email_revert_address_taken',
    });
  });

  it('reads the address again once when a change lands mid-revert, then gives up', async () => {
    const t = setup();
    const { session } = await t.signedInUser();
    const after = await changed(t, session, NEW);
    const users = t.stores.users;
    const real = users.changeEmail.bind(users);
    let calls = 0;

    users.changeEmail = async (id, change) => (++calls === 1 ? 'stale' : real(id, change));

    expect((await t.auth.revertEmailChange({ token: after.revert, meta: meta() })).ok).toBe(true);
    expect(calls).toBe(2);

    const u = setup();
    const signed = await u.signedInUser();
    const other = await changed(u, signed.session, NEW);

    u.stores.users.changeEmail = async () => 'stale';

    expect(await u.auth.revertEmailChange({ token: other.revert, meta: meta() })).toMatchObject({
      ok: false,
      reason: 'email_revert_stale',
    });
  });

  it('refuses a link whose user is gone or whose stored address is unreadable', async () => {
    const t = setup();
    const { session } = await t.signedInUser();
    const after = await changed(t, session, NEW);

    await t.stores.users.softDelete(session.userId);

    expect(await t.auth.revertEmailChange({ token: after.revert, meta: meta() })).toMatchObject({
      ok: false,
      reason: 'user_missing',
    });

    const forged = await t.auth.context.tokens.issueLink('email-revert', 'someone', 60_000, {});

    expect(await t.auth.revertEmailChange({ token: forged.token, meta: meta() })).toMatchObject({
      ok: false,
      reason: 'user_missing',
    });
  });

  it('a revert to the address the account already has still locks it down without a block', async () => {
    const t = setup();
    const { session } = await t.signedInUser();

    const token = await t.auth.context.tokens.issueLink('email-revert', session.userId, 60_000, {
      email: 'ada@example.com',
    });

    expect((await t.auth.revertEmailChange({ token: token.token, meta: meta() })).ok).toBe(true);
    expect(await t.auth.context.tokens.findLive('email-change-block', session.userId)).toBeNull();
    expect((await t.stores.users.findCredentialById(session.userId))?.passwordHash).toBeNull();
  });

  it('is rate limited per IP', async () => {
    const t = setup({ throttle: { doors: { 'email-change-revert': { limit: 1, window: '1m' } } } });

    await t.auth.revertEmailChange({ token: 'a', meta: meta() });

    expect(await t.auth.revertEmailChange({ token: 'a', meta: meta() })).toMatchObject({
      ok: false,
      code: 'rate_limited',
    });
  });
});

describe('email change configuration', () => {
  it('refuses link mode without its URL, a short revert window and a bad code length', () => {
    expect(() =>
      setup({ emailChange: { kind: 'link' }, urls: { resetPassword: (x) => x } }),
    ).toThrow('urls.confirmEmailChange is required');

    expect(() => setup({ emailChange: { revertTtl: '6d' } })).toThrow('at least 7 days');

    expect(() => setup({ emailChange: { digits: 5 } })).toThrow(
      'emailChange.digits must be 6 to 9',
    );
  });

  it('throws a configuration error when the store or the revert URL is missing', async () => {
    const t = setup({ urls: { resetPassword: (x) => x, verifyEmail: (x) => x } });
    const { session } = await t.signedInUser();

    await expect(
      t.auth.requestEmailChange({ session, newEmail: NEW, meta: meta() }),
    ).rejects.toThrow('urls.revertEmailChange is required');

    const u = setup();
    const signed = await u.signedInUser();

    // An adapter written before `changeEmail` existed.
    (u.stores.users as unknown as { changeEmail: undefined }).changeEmail = undefined;

    for (const run of [
      () => u.auth.requestEmailChange({ session: signed.session, newEmail: NEW, meta: meta() }),
      () => u.auth.confirmEmailChangeCode({ session: signed.session, code: '1', meta: meta() }),
      () => u.auth.confirmEmailChangeLink({ token: '1', session: null, meta: meta() }),
      () => u.auth.revertEmailChange({ token: '1', meta: meta() }),
    ])
      await expect(run()).rejects.toThrow('user store with changeEmail');
  });
});
