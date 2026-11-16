import { describe, expect, it } from 'vitest';
import { refuse, toPublicError } from '../../src';
import { plainHasher } from '../../src/testing';
import { accountKey } from '../../src/throttle';
import { meta, NEW_PASSWORD, PASSWORD, setup } from './setup';

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
    expect(cookie.attributes).toMatchObject({ httpOnly: true, secure: true, sameSite: 'lax', path: '/' });
    expect(cookie.attributes.maxAge).toBeUndefined();
    expect(await sessionOf(token)).not.toBeNull();
    expect(audit.types()).toEqual(expect.arrayContaining(['session.created', 'login.success']));
  });

  it('gives remember-me sessions a persistent cookie', async () => {
    const { auth } = await registered();
    const result = await auth.login({ email: EMAIL, password: PASSWORD, rememberMe: true, meta: meta() });
    expect(result.ok && result.value.kind === 'session' && result.value.session.cookie.attributes.maxAge).toBe(30 * 24 * 3600);
  });

  it('answers an unknown address, a wrong password and a malformed address the same', async () => {
    const { auth } = await registered();
    const answers = await Promise.all([
      auth.login({ email: 'nobody@example.com', password: PASSWORD, meta: meta() }),
      auth.login({ email: EMAIL, password: 'wrong passphrase!', meta: meta() }),
      auth.login({ email: 'nope', password: PASSWORD, meta: meta() }),
    ]);
    expect(answers.map((a) => !a.ok && toPublicError(a))).toEqual([
      { code: 'invalid_credentials' },
      { code: 'invalid_credentials' },
      { code: 'invalid_credentials' },
    ]);
  });

  it('pays a full verify for an unknown address', async () => {
    let verifies = 0;
    const base = plainHasher();
    const hasher = { ...base, verify: async (h: string, p: string) => (verifies++, base.verify(h, p)) };
    const { auth } = setup({ password: { hasher, breachCheck: false } });
    await auth.login({ email: 'nobody@example.com', password: PASSWORD, meta: meta() });
    expect(verifies).toBe(1);
  });

  it('caps one source at 5 attempts per account without locking the owner out from elsewhere', async () => {
    const { auth } = await registered();
    for (let i = 0; i < 5; i++) await auth.login({ email: EMAIL, password: 'wrong passphrase!', meta: meta('192.0.2.66') });
    const attacker = await auth.login({ email: EMAIL, password: PASSWORD, meta: meta('192.0.2.66') });
    expect(!attacker.ok && attacker.reason).toBe('account_ip_budget');
    expect(!attacker.ok && toPublicError(attacker)).toEqual({ code: 'invalid_credentials' });
    const owner = await auth.login({ email: EMAIL, password: PASSWORD, meta: meta('198.51.100.20') });
    expect(owner.ok).toBe(true);
  });

  it('locks the account after 10 failures from many sources, mails the owner once and answers like a wrong password', async () => {
    const { auth, mailer, clock } = await registered();
    for (let i = 0; i < 11; i++) await auth.login({ email: EMAIL, password: 'wrong passphrase!', meta: meta(`192.0.2.${i}`) });
    expect(mailer.sent.filter((m) => m.type === 'lockout')).toHaveLength(1);
    const locked = await auth.login({ email: EMAIL, password: PASSWORD, meta: meta('198.51.100.20') });
    expect(!locked.ok && locked.reason).toBe('locked');
    expect(!locked.ok && toPublicError(locked)).toEqual({ code: 'invalid_credentials' });
    clock.advance(5 * 60_000);
    expect((await auth.login({ email: EMAIL, password: PASSWORD, meta: meta('198.51.100.20') })).ok).toBe(true);
  });

  it('does the same lockout work for an unknown address (no existence oracle)', async () => {
    const { auth, mailer } = setup();
    for (let i = 0; i < 11; i++) await auth.login({ email: 'ghost@example.com', password: 'wrong passphrase!', meta: meta(`192.0.2.${i}`) });
    const after = await auth.login({ email: 'ghost@example.com', password: PASSWORD, meta: meta('198.51.100.20') });
    expect(!after.ok && after.reason).toBe('locked');
    expect(mailer.sent.filter((m) => m.type === 'lockout')).toHaveLength(0);
  });

  it('rehashes a hash made with older parameters', async () => {
    const env = setup({ password: { hasher: plainHasher(1), breachCheck: false } });
    await env.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });
    const upgraded = setup({ password: { hasher: plainHasher(2), breachCheck: false } });
    // Share the stores of the first instance with a hasher on new parameters.
    const { createAuth } = await import('../../src');
    const auth = createAuth({ stores: env.stores, password: { hasher: plainHasher(2) }, mailer: upgraded.mailer, secret: 'x'.repeat(32), urls: { resetPassword: (t) => t }, audit: upgraded.audit });
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
    expect(result).toMatchObject({ ok: true, value: { kind: 'challenge', challenge: 'pending-123', methods: ['totp'] } });
    expect(seen).toEqual([0]);
    const user = await stores.users.findCredentialByEmail(EMAIL as never);
    expect(await stores.sessions.listByUser(user?.id ?? '')).toHaveLength(0);
  });

  it('lets a beforeSessionCreate refusal read like a wrong password', async () => {
    const { auth } = await registered({ hooks: { beforeSessionCreate: () => refuse('membership_ended') } });
    const result = await auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });
    expect(!result.ok && [result.code, result.reason]).toEqual(['invalid_credentials', 'membership_ended']);
  });

  it('refuses the session when a revocation lands between the password check and the mint', async () => {
    const base = plainHasher();
    let revokeDuringVerify: (() => Promise<void>) | null = null;
    const hasher = {
      ...base,
      verify: async (hash: string, password: string) => {
        if (revokeDuringVerify) await revokeDuringVerify();
        return base.verify(hash, password);
      },
    };
    const env = await registered({ password: { hasher, breachCheck: false } });
    const user = await env.stores.users.findCredentialByEmail(EMAIL as never);
    revokeDuringVerify = async () => {
      await env.auth.context.sessions.revokeAll(user?.id ?? '');
    };
    const result = await env.auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });
    expect(!result.ok && result.reason).toBe('epoch_fence');
  });

  it('refuses a password longer than the policy without hashing it', async () => {
    const { auth } = await registered();
    const result = await auth.login({ email: EMAIL, password: 'x'.repeat(10_000), meta: meta() });
    expect(!result.ok && result.code).toBe('invalid_credentials');
  });

  it('makes the same store calls and the same verify for a known, an unknown and a locked address', async () => {
    const calls: string[] = [];
    let verifies = 0;
    const base = plainHasher();
    const hasher = { ...base, verify: async (h: string, p: string) => (verifies++, base.verify(h, p)) };
    const env = setup({ password: { hasher, breachCheck: false } });
    await env.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });
    const users = env.stores.users;
    for (const name of ['findCredentialByEmail', 'findCredentialById', 'findById'] as const) {
      const original = users[name].bind(users) as (...args: never[]) => unknown;
      (users as unknown as Record<string, unknown>)[name] = (...args: never[]) => (calls.push(name), original(...args));
    }
    const trace = async (email: string, ip: string) => {
      calls.length = 0;
      verifies = 0;
      await env.auth.login({ email, password: 'wrong passphrase!', meta: meta(ip) });
      return { calls: [...calls], verifies };
    };
    const known = await trace(EMAIL, '192.0.2.1');
    const unknown = await trace('ghost@example.com', '192.0.2.1');
    expect(unknown).toEqual(known);
    expect(known.verifies).toBe(1);
    for (let i = 0; i < 11; i++) await env.auth.login({ email: EMAIL, password: 'wrong passphrase!', meta: meta(`192.0.2.${10 + i}`) });
    expect(await trace(EMAIL, '198.51.100.1')).toEqual(known);
  });

  it('does not wait for the lockout audit row or mail before answering', async () => {
    const env = setup();
    await env.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });
    // From now on the mailer hangs forever.
    env.mailer.send = () => new Promise<void>(() => undefined);
    for (let i = 0; i < 10; i++) await env.auth.login({ email: EMAIL, password: 'wrong passphrase!', meta: meta(`192.0.2.${i}`) });
    // The eleventh attempt sets the lock; the mailer never resolves, the login must still answer.
    const answer = await Promise.race([
      env.auth.login({ email: EMAIL, password: 'wrong passphrase!', meta: meta('192.0.2.99') }),
      new Promise<'hung'>((resolve) => setTimeout(() => resolve('hung'), 500)),
    ]);
    expect(answer !== 'hung' && !answer.ok && answer.reason).toBe('locked');
  });

  it('probe A: the owner on a known device signs in every hour while an attacker keeps the account locked', async () => {
    const { auth, clock } = await registered();
    const first = await auth.login({ email: EMAIL, password: PASSWORD, meta: meta('203.0.113.5') });
    if (!first.ok || first.value.kind !== 'session') throw new Error('first login failed');
    let deviceToken = first.value.session.deviceCookie.value;
    for (let hour = 0; hour < 24; hour++) {
      for (let i = 0; i < 30; i++) await auth.login({ email: EMAIL, password: 'wrong passphrase!', meta: meta(`192.0.${hour}.${i}`) });
      const stranger = await auth.login({ email: EMAIL, password: PASSWORD, meta: meta('198.51.100.20') });
      expect(!stranger.ok && stranger.reason).toBe('locked');
      const owner = await auth.login({ email: EMAIL, password: PASSWORD, deviceToken, meta: meta('203.0.113.5') });
      if (!owner.ok || owner.value.kind !== 'session') throw new Error(`hour ${hour}: owner refused`);
      deviceToken = owner.value.session.deviceCookie.value;
      clock.advance(60 * 60_000);
    }
  });

  it('issues the device cookie only with a session, never at a second-factor challenge', async () => {
    const { auth } = await registered({ hooks: { loginChallenge: () => ({ challenge: 'pending', methods: ['totp'] }) } });
    const result = await auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });
    expect(result.ok && result.value).toEqual({ kind: 'challenge', challenge: 'pending', methods: ['totp'] });
  });

  it('probe I: old device tokens are void after a reset, and many tokens add no guesses', async () => {
    const env = setup({ passwordReset: { kind: 'code' } });
    await env.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });
    const mint = async (i: number) => {
      const r = await env.auth.login({ email: EMAIL, password: PASSWORD, meta: meta(`203.0.113.${i}`) });
      if (!r.ok || r.value.kind !== 'session') throw new Error('login failed');
      return r.value.session.deviceCookie.value;
    };
    const old: string[] = [];
    for (let i = 0; i < 10; i++) old.push(await mint(i));

    // A password reset bumps the epoch.
    await env.auth.requestPasswordReset({ email: EMAIL, meta: meta() });
    await new Promise((resolve) => setTimeout(resolve, 20));
    const code = env.mailer.last('password-reset-code')?.code ?? '';
    const ticket = await env.auth.verifyPasswordResetCode({ email: EMAIL, code, meta: meta() });
    if (!ticket.ok) throw new Error(ticket.reason);
    expect((await env.auth.resetPassword({ token: ticket.value.ticket, password: NEW_PASSWORD, meta: meta() })).ok).toBe(true);

    // The account gets locked by a distributed attack.
    for (let i = 0; i < 11; i++) await env.auth.login({ email: EMAIL, password: 'wrong passphrase!', meta: meta(`192.0.2.${i}`) });
    // Old tokens: even the right new password is refused while locked.
    for (const [i, deviceToken] of old.entries()) {
      const r = await env.auth.login({ email: EMAIL, password: NEW_PASSWORD, deviceToken, meta: meta(`203.0.113.${i}`) });
      expect(!r.ok && r.reason).toBe('locked');
    }

    // Ten fresh, valid tokens (minted after the lock expires) give five guesses in all, not fifty.
    env.clock.advance(60 * 60_000);
    const fresh: string[] = [];
    for (let i = 0; i < 10; i++) {
      const r = await env.auth.login({ email: EMAIL, password: NEW_PASSWORD, meta: meta(`198.18.0.${i}`) });
      if (!r.ok || r.value.kind !== 'session') throw new Error(`fresh login ${i} failed`);
      fresh.push(r.value.session.deviceCookie.value);
    }
    for (let i = 0; i < 11; i++) await env.auth.login({ email: EMAIL, password: 'wrong passphrase!', meta: meta(`198.51.100.${i}`) });
    let letThrough = 0;
    for (let i = 0; i < 50; i++) {
      const deviceToken = fresh[i % fresh.length];
      const r = await env.auth.login({ email: EMAIL, password: 'guess number ' + String(i).padStart(4, '0'), deviceToken, meta: meta(`203.0.113.${i}`) });
      if (!r.ok && r.reason === 'wrong_password') letThrough++;
    }
    expect(letThrough).toBe(5);
    // Even the right password is now refused on every token until the window ends.
    const owner = await env.auth.login({ email: EMAIL, password: NEW_PASSWORD, deviceToken: fresh[0], meta: meta('198.18.1.1') });
    expect(!owner.ok && owner.reason).toBe('device_budget');
  });

  it('never spends a device budget on correct logins while the account is unlocked', async () => {
    const { auth, clock } = await registered();
    let deviceToken: string | undefined;
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
    for (let i = 0; i < 11; i++) await auth.login({ email: EMAIL, password: 'wrong passphrase!', meta: meta(`192.0.2.${i}`) });

    const owner = await auth.login({ email: EMAIL, password: PASSWORD, deviceToken, meta: meta('203.0.113.5') });
    if (!owner.ok || owner.value.kind !== 'session') throw new Error('owner refused under the lock');
    deviceToken = owner.value.session.deviceCookie.value;

    const account = accountKey(EMAIL as never);
    for (let i = 0; i < 5; i++) {
      const r = await auth.login({ email: EMAIL, password: 'wrong passphrase!', deviceToken, meta: meta(`198.51.100.${i}`) });
      expect(!r.ok && r.reason).toBe('wrong_password');
    }
    expect((await stores.counters.get(`acct:${account}`))?.count).toBe(5);
    const sixth = await auth.login({ email: EMAIL, password: PASSWORD, deviceToken, meta: meta('203.0.113.5') });
    expect(!sixth.ok && sixth.reason).toBe('device_budget');
  });

  it('probe E: a rehash finishing after a password change cannot bring the old password back', async () => {
    const env = setup({ password: { hasher: plainHasher(1), breachCheck: false } });
    await env.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });
    const user = await env.stores.users.findCredentialByEmail(EMAIL as never);
    if (!user) throw new Error('no user');
    const { createAuth } = await import('../../src');
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => (release = resolve));
    const slow = plainHasher(2);
    // The new-parameter hash stalls until the password change has landed.
    const hasher = { ...slow, hash: async (p: string) => (await gate, slow.hash(p)) };
    const auth = createAuth({ stores: env.stores, password: { hasher, breachCheck: false }, mailer: env.mailer, secret: 'x'.repeat(32), urls: { resetPassword: (t) => t }, audit: env.audit, clock: env.clock });
    const login = auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });
    await new Promise((resolve) => setTimeout(resolve, 10));
    // A password change lands while the rehash is in flight.
    await env.stores.users.setPasswordHash(user.id, 'plain$v1$changed-elsewhere');
    release();
    expect((await login).ok).toBe(true);
    expect((await env.stores.users.findCredentialById(user.id))?.passwordHash).toBe('plain$v1$changed-elsewhere');
    expect(env.audit.types()).not.toContain('password.rehashed');
  });
});
