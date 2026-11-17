import { describe, expect, it } from 'vitest';
import { refuse } from '../../src';
import { plainHasher } from '../../src/testing';
import { accountKey } from '../../src/throttle/counter-keys';
import { meta, PASSWORD, setup } from './setup';

const EMAIL = 'ada@example.com';

async function registered(overrides: Parameters<typeof setup>[0] = {}) {
  const env = setup(overrides);

  await env.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });

  return env;
}

describe('login', () => {
  it('issues a session with a __Host- cookie on the right password', async () => {
    const { auth, sessionOf, audit } = await registered();
    const result = await auth.login({ email: 'ADA@example.com', password: PASSWORD, meta: meta() });

    if (!result.ok || result.value.kind !== 'session') throw new Error('expected a session');

    const { cookie, token } = result.value.session;

    expect(cookie.name).toBe('__Host-session');

    expect(cookie.attributes).toMatchObject({
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/',
    });

    expect(cookie.attributes.maxAge).toBeUndefined();
    expect(await sessionOf(token)).not.toBeNull();
    expect(audit.types()).toEqual(expect.arrayContaining(['session.created', 'login.success']));
  });

  it('gives remember-me sessions a persistent cookie', async () => {
    const { auth } = await registered();

    const result = await auth.login({
      email: EMAIL,
      password: PASSWORD,
      rememberMe: true,
      meta: meta(),
    });

    expect(
      result.ok && result.value.kind === 'session' && result.value.session.cookie.attributes.maxAge,
    ).toBe(30 * 24 * 3600);
  });

  it('rehashes a hash made with older parameters', async () => {
    const env = setup({ password: { hasher: plainHasher(1), breachCheck: false } });

    await env.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });
    const upgraded = setup({ password: { hasher: plainHasher(2), breachCheck: false } });
    // Share the stores of the first instance with a hasher on new parameters.
    const { createAuth } = await import('../../src');

    const auth = createAuth({
      stores: env.stores,
      password: { hasher: plainHasher(2) },
      mailer: upgraded.mailer,
      secret: 'x'.repeat(32),
      urls: { resetPassword: (t) => t },
      audit: upgraded.audit,
    });

    expect((await auth.login({ email: EMAIL, password: PASSWORD, meta: meta() })).ok).toBe(true);
    const stored = await env.stores.users.findCredentialByEmail(EMAIL as never);

    expect(stored?.passwordHash?.startsWith('plain$v2$')).toBe(true);
    expect(upgraded.audit.types()).toContain('password.rehashed');
  });

  it('hands the login to a second-factor challenge without issuing a session', async () => {
    const seen: number[] = [];

    const { auth, stores } = await registered({
      hooks: {
        loginChallenge: ({ epoch }) => {
          seen.push(epoch);

          return { challenge: 'pending-123', methods: ['totp'] };
        },
      },
    });

    const result = await auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    expect(result).toMatchObject({
      ok: true,
      value: { kind: 'challenge', challenge: 'pending-123', methods: ['totp'] },
    });

    expect(seen).toEqual([0]);
    const user = await stores.users.findCredentialByEmail(EMAIL as never);

    expect(await stores.sessions.listByUser(user?.id ?? '')).toHaveLength(0);
  });

  it('lets a beforeSessionCreate refusal read like a wrong password', async () => {
    const { auth } = await registered({
      hooks: { beforeSessionCreate: () => refuse('membership_ended') },
    });

    const result = await auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    expect(!result.ok && [result.code, result.reason]).toEqual([
      'invalid_credentials',
      'membership_ended',
    ]);
  });

  it('issues the device cookie only with a session, never at a second-factor challenge', async () => {
    const { auth } = await registered({
      hooks: { loginChallenge: () => ({ challenge: 'pending', methods: ['totp'] }) },
    });

    const result = await auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    expect(result.ok && result.value).toEqual({
      kind: 'challenge',
      challenge: 'pending',
      methods: ['totp'],
    });
  });

  it('never spends a device budget on correct logins while the account is unlocked', async () => {
    const { auth, clock } = await registered();
    let deviceToken: string | null = null;

    for (let i = 0; i < 10; i++) {
      const r = await auth.login({ email: EMAIL, password: PASSWORD, deviceToken, meta: meta() });

      if (!r.ok || r.value.kind !== 'session') throw new Error(`login ${i} refused`);

      deviceToken = r.value.session.deviceCookie.value;
      clock.advance(60_000);
    }
  });

  it('under a lock, lets the owner in with the cookie and counts wrong guesses against the device and the account', async () => {
    const { auth, stores } = await registered();
    const first = await auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    if (!first.ok || first.value.kind !== 'session') throw new Error('first login failed');

    let deviceToken = first.value.session.deviceCookie.value;

    for (let i = 0; i < 11; i++)
      await auth.login({ email: EMAIL, password: 'wrong passphrase!', meta: meta(`192.0.2.${i}`) });

    const owner = await auth.login({
      email: EMAIL,
      password: PASSWORD,
      deviceToken,
      meta: meta('203.0.113.5'),
    });

    if (!owner.ok || owner.value.kind !== 'session')
      throw new Error('owner refused under the lock');

    deviceToken = owner.value.session.deviceCookie.value;

    const account = accountKey(EMAIL as never);

    for (let i = 0; i < 5; i++) {
      const r = await auth.login({
        email: EMAIL,
        password: 'wrong passphrase!',
        deviceToken,
        meta: meta(`198.51.100.${i}`),
      });

      expect(!r.ok && r.reason).toBe('wrong_password');
    }

    expect((await stores.counters.get(`acct:${account}`))?.count).toBe(5);

    const sixth = await auth.login({
      email: EMAIL,
      password: PASSWORD,
      deviceToken,
      meta: meta('203.0.113.5'),
    });

    expect(!sixth.ok && sixth.reason).toBe('device_budget');
  });
});
