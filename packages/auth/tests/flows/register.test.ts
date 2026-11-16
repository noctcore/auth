import { describe, expect, it } from 'vitest';
import { AuthConfigError, toPublicError } from '../../src';
import { meta, PASSWORD, setup } from './setup';

describe('register', () => {
  it('creates the account, sends an 8-digit verification code and issues no session', async () => {
    const { auth, mailer, audit } = setup();
    const result = await auth.register({
      email: ' Ada@Example.com ',
      password: PASSWORD,
      meta: meta(),
    });
    expect(result).toEqual({ ok: true, value: { session: null } });
    const mail = mailer.last('verify-email');
    expect(mail?.to).toBe('ada@example.com');
    expect(mail?.code).toMatch(/^\d{8}$/u);
    expect(audit.types()).toContain('register.created');
  });

  it('answers a taken address exactly like a new one and mails the owner instead', async () => {
    const { auth, mailer, audit } = setup();
    const first = await auth.register({
      email: 'ada@example.com',
      password: PASSWORD,
      meta: meta(),
    });
    const sentBefore = mailer.sent.length;
    const second = await auth.register({
      email: 'ADA@example.com',
      password: 'a different passphrase',
      meta: meta(),
    });
    expect(second).toEqual(first);
    const newMail = mailer.sent.slice(sentBefore);
    expect(newMail.map((m) => m.type)).toEqual(['account-exists']);
    expect(audit.types()).toContain('register.existing');
  });

  it('says email_in_use only when the app opts into revealing it', async () => {
    const { auth } = setup({ registration: { revealExisting: true } });
    await auth.register({ email: 'ada@example.com', password: PASSWORD, meta: meta() });
    const again = await auth.register({
      email: 'ada@example.com',
      password: PASSWORD,
      meta: meta(),
    });
    expect(!again.ok && toPublicError(again)).toEqual({ code: 'email_in_use' });
  });

  it('refuses autoLogin without revealExisting at startup', () => {
    expect(() => setup({ registration: { autoLogin: true } })).toThrow(AuthConfigError);
  });

  it('issues a session on registration with autoLogin', async () => {
    const { auth, sessionOf } = setup({ registration: { revealExisting: true, autoLogin: true } });
    const result = await auth.register({
      email: 'ada@example.com',
      password: PASSWORD,
      meta: meta(),
    });
    expect(result.ok && result.value.session).toBeTruthy();
    if (result.ok && result.value.session)
      expect(await sessionOf(result.value.session.token)).not.toBeNull();
  });

  it('refuses short, overlong and breached passwords before touching the user store', async () => {
    const { auth, stores } = setup({
      password: {
        hasher: (await import('../../src/testing')).plainHasher(),
        breachCheck: async (pw) => (pw === 'password1234567' ? 'breached' : 'clean'),
      },
    });
    const short = await auth.register({ email: 'a@example.com', password: 'short', meta: meta() });
    const long = await auth.register({
      email: 'b@example.com',
      password: 'x'.repeat(300),
      meta: meta(),
    });
    const breached = await auth.register({
      email: 'c@example.com',
      password: 'password1234567',
      meta: meta(),
    });
    expect([short, long, breached].map((r) => !r.ok && r.code)).toEqual([
      'weak_password',
      'password_too_long',
      'breached_password',
    ]);
    expect(await stores.users.findById('1')).toBeNull();
  });

  it('accepts the password when the breach check is unavailable (fails open, counted)', async () => {
    const counted: string[] = [];
    const { auth } = setup({
      password: {
        hasher: (await import('../../src/testing')).plainHasher(),
        breachCheck: async () => 'unavailable',
      },
      metrics: { count: (name, labels) => counted.push(`${name}:${labels?.verdict ?? ''}`) },
    });
    const result = await auth.register({
      email: 'ada@example.com',
      password: PASSWORD,
      meta: meta(),
    });
    expect(result.ok).toBe(true);
    expect(counted).toContain('auth_breach_check:unavailable');
  });

  it('refuses an invalid address and a failed captcha', async () => {
    const { auth } = setup({
      captcha: { verify: async (token) => (token === 'good' ? 'pass' : 'reject') },
    });
    const noCaptcha = await auth.register({
      email: 'ada@example.com',
      password: PASSWORD,
      meta: meta(),
    });
    const badEmail = await auth.register({
      email: 'not-an-email',
      password: PASSWORD,
      captchaToken: 'good',
      meta: meta(),
    });
    expect(!noCaptcha.ok && noCaptcha.code).toBe('captcha_failed');
    expect(!badEmail.ok && badEmail.code).toBe('invalid_email');
  });

  it('rate limits the door per IP', async () => {
    const { auth } = setup({ throttle: { doors: { register: { limit: 2, window: '1m' } } } });
    for (const n of [1, 2])
      await auth.register({ email: `u${n}@example.com`, password: PASSWORD, meta: meta() });
    const third = await auth.register({
      email: 'u3@example.com',
      password: PASSWORD,
      meta: meta(),
    });
    expect(!third.ok && toPublicError(third)).toEqual({
      code: 'rate_limited',
      retryAfterSeconds: 60,
    });
    const otherIp = await auth.register({
      email: 'u4@example.com',
      password: PASSWORD,
      meta: meta('198.51.100.1'),
    });
    expect(otherIp.ok).toBe(true);
  });
});
