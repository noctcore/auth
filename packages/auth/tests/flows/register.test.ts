import { describe, expect, it } from 'vitest';
import { AuthConfigError, toPublicError } from '../../src';
import { meta, PASSWORD, settled, setup } from './setup';

describe('register', () => {
  it('creates the account, sends an 8-digit verification code and issues no session', async () => {
    const { auth, mailer, audit } = setup();

    const result = await auth.register({
      email: ' Ada@Example.com ',
      password: PASSWORD,
      meta: meta(),
    });

    expect(result).toEqual({ ok: true, value: { session: null } });
    await settled();
    const mail = mailer.last('verify-email');

    expect(mail?.to).toBe('ada@example.com');
    expect(mail?.code).toMatch(/^\d{8}$/u);
    expect(audit.types()).toContain('register.created');
  });

  it('sends the verification mail even while the audit sink hangs', async () => {
    const { auth, mailer, audit } = setup();

    audit.emit = () => new Promise<never>(() => undefined);

    await auth.register({ email: 'ada@example.com', password: PASSWORD, meta: meta() });
    await settled();

    expect(mailer.last('verify-email')?.to).toBe('ada@example.com');
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

  it('accepts the password when the breach check is unavailable (fails open, counted)', async () => {
    const counted: string[] = [];

    const { auth } = setup({
      password: {
        hasher: (await import('../../src/testing')).plainHasher(),
        breachCheck: async () => 'unavailable',
      },
      metrics: { count: (name, labels) => counted.push(`${name}:${labels?.['verdict'] ?? ''}`) },
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
