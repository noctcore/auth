import { describe, expect, it } from 'vitest';
import { refuse } from '../../src';
import { meta, NEW_PASSWORD, PASSWORD, setup } from './setup';

const EMAIL = 'ada@example.com';

async function twoDevices(overrides: Parameters<typeof setup>[0] = {}) {
  const t = setup(overrides);
  const laptop = await t.signedInUser(EMAIL);

  const phoneLogin = await t.auth.login({
    email: EMAIL,
    password: PASSWORD,
    meta: meta('198.51.100.2'),
  });

  if (!phoneLogin.ok || phoneLogin.value.kind !== 'session') throw new Error('phone login failed');

  const phone = {
    token: phoneLogin.value.session.token,
    session: phoneLogin.value.session.session,
  };

  return { ...t, laptop, phone };
}

describe('validateRequest', () => {
  it('refuses a missing, malformed or unknown token as session_expired', async () => {
    const t = setup();

    for (const token of [null, 'nope', 'a'.repeat(64)]) {
      const result = await t.auth.validateRequest({ token });

      expect(!result.ok && result.code).toBe('session_expired');
    }
  });

  it('reads the token from a Cookie header', async () => {
    const t = setup();
    const { token } = await t.signedInUser();

    expect(t.auth.readSessionToken(`theme=dark; __Host-session=${token}`)).toBe(token);
    expect(t.auth.readSessionToken(undefined)).toBeNull();
  });

  it('revokes the session when an onSessionValidate hook refuses it', async () => {
    const revoked: string[] = [];
    let allow = true;

    const t = setup({
      hooks: {
        onSessionValidate: () => (allow ? undefined : refuse('membership_ended')),
        onSessionsRevoked: ({ reason }) => void revoked.push(reason),
      },
    });

    const { token } = await t.signedInUser();

    expect(await t.sessionOf(token)).not.toBeNull();
    allow = false;
    const refused = await t.auth.validateRequest({ token });

    expect(!refused.ok && [refused.code, refused.reason]).toEqual([
      'session_expired',
      'membership_ended',
    ]);

    allow = true;
    expect(await t.sessionOf(token)).toBeNull();
    expect(revoked).toEqual(['membership_ended']);
  });
});

describe('fresh authentication', () => {
  it('goes stale after 10 minutes and is renewed by re-entering the password', async () => {
    const t = setup();
    const { session } = await t.signedInUser();

    expect(t.auth.requireFreshAuth(session).ok).toBe(true);
    t.clock.advance(10 * 60_000 + 1);

    expect(t.auth.requireFreshAuth(session)).toMatchObject({
      ok: false,
      code: 'fresh_auth_required',
    });

    const wrong = await t.auth.reauthenticate({
      session,
      password: 'wrong passphrase!',
      meta: meta(),
    });

    expect(!wrong.ok && wrong.code).toBe('invalid_credentials');
    const renewed = await t.auth.reauthenticate({ session, password: PASSWORD, meta: meta() });

    if (!renewed.ok) throw new Error(renewed.reason);

    expect(t.auth.requireFreshAuth(renewed.value.session).ok).toBe(true);
  });
});

describe('changePassword', () => {
  it('refuses a wrong current password and counts it toward the lockout', async () => {
    const t = setup({ throttle: { lockout: { perAccount: { limit: 2, window: '15m' } } } });
    const { session } = await t.signedInUser();

    for (let i = 0; i < 3; i++) {
      const result = await t.auth.changePassword({
        session,
        currentPassword: 'wrong passphrase!',
        newPassword: NEW_PASSWORD,
        meta: meta(),
      });

      expect(!result.ok && result.code).toBe('invalid_credentials');
    }

    expect(t.mailer.last('lockout')?.to).toBe(EMAIL);
    // Where the guesses came from, for the owner's notice.
    expect(t.mailer.last('lockout')?.meta).toEqual({ ip: meta().ip, userAgent: 'vitest' });

    const login = await t.auth.login({
      email: EMAIL,
      password: PASSWORD,
      meta: meta('198.51.100.30'),
    });

    expect(!login.ok && login.reason).toBe('locked');
  });

  it('asks the second-factor seam and the policy before writing', async () => {
    const t = setup({
      hooks: {
        beforePasswordChange: ({ secondFactor }) =>
          secondFactor ? undefined : refuse('totp_required', 'second_factor_required'),
      },
    });

    const { session } = await t.signedInUser();

    const missing = await t.auth.changePassword({
      session,
      currentPassword: PASSWORD,
      newPassword: NEW_PASSWORD,
      meta: meta(),
    });

    expect(!missing.ok && missing.code).toBe('second_factor_required');

    const weak = await t.auth.changePassword({
      session,
      currentPassword: PASSWORD,
      newPassword: 'short',
      secondFactor: '1',
      meta: meta(),
    });

    expect(!weak.ok && weak.code).toBe('weak_password');
    expect((await t.auth.login({ email: EMAIL, password: PASSWORD, meta: meta() })).ok).toBe(true);
  });

  it('answers password_not_set for an account without a password', async () => {
    const t = setup();
    const { session } = await t.signedInUser();

    await t.stores.users.clearPassword(session.userId);

    const result = await t.auth.changePassword({
      session,
      currentPassword: PASSWORD,
      newPassword: NEW_PASSWORD,
      meta: meta(),
    });

    expect(!result.ok && result.code).toBe('password_not_set');
  });
});

describe('session management', () => {
  it('lists the active sessions, newest activity first, marking the current one', async () => {
    const t = await twoDevices();
    const list = await t.auth.sessions.list(t.phone.session);

    expect(list).toHaveLength(2);
    expect(list.find((s) => s.current)?.handle).toBe(t.auth.sessions.handle(t.phone.session.id));
    expect(list.map((s) => s.ip).sort()).toEqual(['198.51.100.2', '203.0.113.7']);
  });

  it('needs fresh authentication to revoke another device, but not its own', async () => {
    const t = await twoDevices();

    t.clock.advance(11 * 60_000);

    const stale = await t.auth.sessions.revoke({
      session: t.laptop.session,
      handle: t.auth.sessions.handle(t.phone.session.id),
      meta: meta(),
    });

    expect(!stale.ok && stale.code).toBe('fresh_auth_required');

    const renewed = await t.auth.reauthenticate({
      session: t.laptop.session,
      password: PASSWORD,
      meta: meta(),
    });

    if (!renewed.ok) throw new Error(renewed.reason);

    const revoked = await t.auth.sessions.revoke({
      session: renewed.value.session,
      handle: t.auth.sessions.handle(t.phone.session.id),
      meta: meta(),
    });

    expect(revoked).toEqual({ ok: true, value: { revoked: true } });
    expect(await t.sessionOf(t.phone.token)).toBeNull();

    const self = await t.auth.sessions.revoke({
      session: renewed.value.session,
      handle: t.auth.sessions.handle(renewed.value.session.id),
      meta: meta(),
    });

    expect(self).toEqual({ ok: true, value: { revoked: true } });
  });

  it('reads freshness for revoking a device from the live session, not the object passed', async () => {
    const t = await twoDevices();

    t.clock.advance(11 * 60_000);

    const claimed = { ...t.laptop.session, authenticatedAt: t.clock.now() };

    const result = await t.auth.sessions.revoke({
      session: claimed,
      handle: t.auth.sessions.handle(t.phone.session.id),
      meta: meta(),
    });

    expect(!result.ok && result.code).toBe('fresh_auth_required');
    expect(await t.sessionOf(t.phone.token)).not.toBeNull();
  });

  it('refuses to revoke a device from a session that is no longer live, or names another user', async () => {
    const t = await twoDevices();
    const eve = await t.signedInUser('eve@example.com', '192.0.2.99');
    const borrowed = { ...eve.session, userId: t.laptop.session.userId };

    const relabelled = await t.auth.sessions.revoke({
      session: borrowed,
      handle: t.auth.sessions.handle(t.phone.session.id),
      meta: meta(),
    });

    expect(!relabelled.ok && relabelled.code).toBe('session_expired');

    await t.auth.logout({ token: t.laptop.token, meta: meta() });

    const dead = await t.auth.sessions.revoke({
      session: t.laptop.session,
      handle: t.auth.sessions.handle(t.phone.session.id),
      meta: meta(),
    });

    expect(!dead.ok && dead.code).toBe('session_expired');
    expect(await t.sessionOf(t.phone.token)).not.toBeNull();
  });

  it("cannot revoke another user's session", async () => {
    const t = await twoDevices();
    const eve = await t.signedInUser('eve@example.com', '192.0.2.99');

    const result = await t.auth.sessions.revoke({
      session: eve.session,
      handle: t.auth.sessions.handle(t.phone.session.id),
      meta: meta(),
    });

    expect(result).toEqual({ ok: true, value: { revoked: false } });
    expect(await t.sessionOf(t.phone.token)).not.toBeNull();
  });

  it('needs fresh authentication to sign out every other device', async () => {
    const t = await twoDevices();

    t.clock.advance(11 * 60_000);
    const stale = await t.auth.sessions.revokeOthers({ session: t.laptop.session, meta: meta() });

    expect(!stale.ok && stale.code).toBe('fresh_auth_required');
    expect(await t.sessionOf(t.phone.token)).not.toBeNull();
  });

  it('reads freshness from the live session, not from the object the caller passes', async () => {
    const t = await twoDevices();

    t.clock.advance(11 * 60_000);

    const claimed = { ...t.laptop.session, authenticatedAt: t.clock.now() };
    const result = await t.auth.sessions.revokeOthers({ session: claimed, meta: meta() });

    expect(!result.ok && result.code).toBe('fresh_auth_required');
    expect(await t.sessionOf(t.phone.token)).not.toBeNull();
  });

  it('signs out every other device and keeps this one', async () => {
    const t = await twoDevices();
    const result = await t.auth.sessions.revokeOthers({ session: t.laptop.session, meta: meta() });

    if (!result.ok) throw new Error(result.reason);

    expect(await t.sessionOf(t.phone.token)).toBeNull();
    expect(await t.sessionOf(t.laptop.token)).toBeNull();
    expect(await t.sessionOf(result.value.token)).not.toBeNull();
  });

  it('signs out everywhere and returns a blank cookie', async () => {
    const t = await twoDevices();
    const { cookie } = await t.auth.sessions.revokeAll({ session: t.laptop.session, meta: meta() });

    expect(cookie).toMatchObject({ name: '__Host-session', value: '', attributes: { maxAge: 0 } });
    expect(await t.sessionOf(t.phone.token)).toBeNull();
    expect(await t.sessionOf(t.laptop.token)).toBeNull();
  });

  it('logs out one device, and answers an unknown token with the same blank cookie', async () => {
    const t = await twoDevices();
    const out = await t.auth.logout({ token: t.laptop.token, meta: meta() });
    const unknown = await t.auth.logout({ token: 'garbage', meta: meta() });

    expect(out).toEqual(unknown);
    expect(await t.sessionOf(t.laptop.token)).toBeNull();
    expect(await t.sessionOf(t.phone.token)).not.toBeNull();
    expect(t.audit.types()).toContain('logout');
  });

  it('evicts the oldest session over the per-user cap and reports it to the hooks', async () => {
    const evicted: string[][] = [];
    const evictedHandles: string[][] = [];

    const t = setup({
      session: { maxPerUser: 2 },
      hooks: {
        onSessionsRevoked: ({ sessionIds, sessionHandles, reason }) => {
          if (reason !== 'evicted') return;

          evicted.push([...sessionIds]);
          evictedHandles.push([...sessionHandles]);
        },
      },
    });

    const first = await t.signedInUser();
    const [listed] = await t.auth.sessions.list(first.session);

    t.clock.advance(1000);
    await t.auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });
    t.clock.advance(1000);
    await t.auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });
    expect(evicted).toEqual([[first.session.id]]);
    expect(evictedHandles).toEqual([[listed?.handle]]);
    expect(await t.sessionOf(first.token)).toBeNull();
  });

  it('tells the hooks the handle the list showed for a revoked session', async () => {
    const heard: { sessionIds: readonly string[]; sessionHandles: readonly string[] }[] = [];

    const t = await twoDevices({
      hooks: {
        onSessionsRevoked: ({ sessionIds, sessionHandles, reason }) =>
          void (reason === 'revoke-one' && heard.push({ sessionIds, sessionHandles })),
      },
    });

    const phone = (await t.auth.sessions.list(t.laptop.session)).find((s) => !s.current);

    const result = await t.auth.sessions.revoke({
      session: t.laptop.session,
      handle: phone?.handle ?? '',
      meta: meta(),
    });

    expect(result).toEqual({ ok: true, value: { revoked: true } });
    expect(heard).toEqual([{ sessionIds: [t.phone.session.id], sessionHandles: [phone?.handle] }]);
    expect(t.auth.sessions.handle(t.phone.session.id)).toBe(phone?.handle);
  });

  it('keeps a handle stable across touches and re-lists, and distinct per session', async () => {
    const t = await twoDevices();
    const before = await t.auth.sessions.list(t.laptop.session);

    t.clock.advance(2 * 60_000);
    await t.sessionOf(t.phone.token);

    const after = await t.auth.sessions.list(t.laptop.session);

    expect(after.map((s) => s.handle).sort()).toEqual(before.map((s) => s.handle).sort());
    expect(new Set(after.map((s) => s.handle)).size).toBe(2);
  });

  it('answers a handle that names nothing with revoked: false and revokes nothing', async () => {
    const t = await twoDevices();

    for (const handle of ['', 'garbage', t.phone.session.id]) {
      const result = await t.auth.sessions.revoke({
        session: t.laptop.session,
        handle,
        meta: meta(),
      });

      expect(result).toEqual({ ok: true, value: { revoked: false } });
    }

    expect(await t.auth.sessions.list(t.laptop.session)).toHaveLength(2);
  });
});
