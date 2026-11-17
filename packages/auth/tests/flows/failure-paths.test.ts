// What the flows do when a dependency fails: an audit sink, a mailer, a hook
// or a captcha provider that throws or cannot answer, a store write that is
// refused, and the startup checks on a config that is missing a piece.
import { describe, expect, it } from 'vitest';

import { createAuth, type AuthConfig, type AuthPlugin } from '../../src';
import type { Logger } from '../../src/ports/logger';
import type { AuthUser } from '../../src/ports/stores';
import { manualClock, memoryStores, plainHasher, recordingMailer } from '../../src/testing';
import { meta, NEW_PASSWORD, PASSWORD, SECRET, setup } from './setup';

const EMAIL = 'ada@example.com';

function recordingLogger() {
  const lines: {
    level: 'warn' | 'error';
    message: string;
    context?: Record<string, unknown> | undefined;
  }[] = [];

  const logger: Logger = {
    warn: (message, context) => void lines.push({ level: 'warn', message, ...{ context } }),
    error: (message, context) => void lines.push({ level: 'error', message, ...{ context } }),
  };

  return { logger, lines };
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

describe('a failing audit sink, mailer or hook', () => {
  it('logs an audit sink that throws and still answers the flow', async () => {
    const { logger, lines } = recordingLogger();

    const { auth } = setup({
      logger,
      audit: {
        emit: async () => {
          throw new Error('audit down');
        },
      },
    });

    const result = await auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });

    expect(result.ok).toBe(true);
    expect(lines.some((l) => l.message === 'Audit sink failed')).toBe(true);
  });

  it('logs a mailer that throws and still answers the flow', async () => {
    const { logger, lines } = recordingLogger();

    const { auth } = setup({
      logger,
      mailer: {
        send: async () => {
          throw new Error('smtp down');
        },
      },
    } as never);

    const result = await auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });

    expect(result.ok).toBe(true);
    expect(lines.some((l) => l.message === 'Mailer failed')).toBe(true);
  });

  it('logs an onSessionsRevoked hook that throws and still revokes', async () => {
    const { logger, lines } = recordingLogger();

    const { auth, signedInUser, sessionOf } = setup({
      logger,
      hooks: {
        onSessionsRevoked: async () => {
          throw new Error('hook down');
        },
      },
    });

    const { token } = await signedInUser(EMAIL);
    const result = await auth.logout({ token, meta: meta() });

    expect(result.cookie.value).toBe('');
    expect(await sessionOf(token)).toBeNull();
    expect(lines.some((l) => l.message === 'onSessionsRevoked hook failed')).toBe(true);
  });

  it('logs a failed lockout notice off the response path', async () => {
    const { logger, lines } = recordingLogger();

    const { auth, signedInUser } = setup({
      logger,
      mailer: {
        send: async (mail: { type: string }) => {
          if (mail.type === 'lockout') throw new Error('smtp down');
        },
      },
      audit: {
        emit: async (event: { type: string }) => {
          if (event.type === 'account.locked') throw new Error('audit down');
        },
      },
    } as never);

    await signedInUser(EMAIL);

    for (let i = 0; i < 11; i++)
      await auth.login({ email: EMAIL, password: 'wrong passphrase!', meta: meta(`192.0.2.${i}`) });

    await tick();

    expect(lines.some((l) => l.message === 'Audit sink failed')).toBe(true);
  });
});

describe('a captcha provider that cannot answer', () => {
  it('answers captcha_unavailable, never a pass', async () => {
    const { auth } = setup({ captcha: { verify: async () => 'unavailable' } });
    const result = await auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    expect(result).toMatchObject({ ok: false, code: 'captcha_unavailable' });
  });
});

describe('session attributes that fail the schema at issue time', () => {
  it('refuses the session as forbidden and logs it', async () => {
    const { logger, lines } = recordingLogger();

    const { auth } = setup({
      logger,
      session: {
        attributes: {
          parse: () => {
            throw new Error('bad attributes');
          },
        },
      },
    } as never);

    await auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });

    const result = await auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    expect(result).toMatchObject({
      ok: false,
      code: 'forbidden',
      reason: 'invalid_session_attributes',
    });

    expect(
      lines.some((l) => l.message === 'Session attributes failed the schema at issue time'),
    ).toBe(true);
  });
});

describe('a rehash that fails', () => {
  it('logs the failure and keeps the login', async () => {
    const { logger, lines } = recordingLogger();
    const env = setup({ logger, password: { hasher: plainHasher(1), breachCheck: false } });

    await env.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });

    const upgraded = setup({
      logger,
      password: {
        hasher: {
          ...plainHasher(2),
          hash: async () => {
            throw new Error('hasher down');
          },
          verify: plainHasher(1).verify,
        },
        breachCheck: false,
      },
    });

    const user = await env.stores.users.findCredentialByEmail(EMAIL as never);

    // Move the registered account into the second instance's stores.
    await upgraded.stores.users.create({
      email: EMAIL as never,
      passwordHash: user?.passwordHash ?? '',
    });

    const result = await upgraded.auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    expect(result.ok).toBe(true);
    expect(lines.some((l) => l.message === 'Password rehash failed')).toBe(true);
  });
});

describe('email verification edges', () => {
  it('rate limits code and link verification per IP', async () => {
    const one = { limit: 1, window: '1m' } as const;
    const env = setup({ throttle: { doors: { 'email-verification': one } } });
    const { session } = await env.signedInUser(EMAIL);

    await env.auth.verifyEmailCode({ session, code: '00000000', meta: meta() });

    const code = await env.auth.verifyEmailCode({ session, code: '00000000', meta: meta() });
    const link = await env.auth.verifyEmailLink({ token: 'x', session, meta: meta() });

    expect(!code.ok && code.code).toBe('rate_limited');
    expect(!link.ok && link.code).toBe('rate_limited');
  });

  it('sends nothing to a verified address and ends a session whose account vanished', async () => {
    const env = setup();
    const { session } = await env.signedInUser(EMAIL);
    const code = env.mailer.last('verify-email')?.code ?? '';

    await env.auth.verifyEmailCode({ session, code, meta: meta() });

    const fresh = await env.auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    if (!fresh.ok || fresh.value.kind !== 'session') throw new Error('login failed');

    const verified = await env.auth.requestEmailVerification({
      session: fresh.value.session.session,
      meta: meta(),
    });

    const ghost = await env.auth.requestEmailVerification({
      session: { ...fresh.value.session.session, userId: 'no-such-user' },
      meta: meta(),
    });

    expect(verified).toEqual({ ok: true, value: { sent: false } });
    expect(ghost).toMatchObject({ ok: false, code: 'session_expired', reason: 'user_missing' });
  });

  it('refuses the code when the verified flag cannot be written', async () => {
    const env = setup();
    const { session } = await env.signedInUser(EMAIL);
    const code = env.mailer.last('verify-email')?.code ?? '';

    env.stores.users.markEmailVerified = async () => false;

    const result = await env.auth.verifyEmailCode({ session, code, meta: meta() });

    expect(result).toMatchObject({
      ok: false,
      code: 'invalid_token',
      reason: 'verification_write_refused',
    });
  });
});

describe('password reset by code with a malformed address', () => {
  it('counts the guess against the raw input and refuses it', async () => {
    const env = setup({ passwordReset: { kind: 'code', enqueue: async () => undefined } });

    const result = await env.auth.verifyPasswordResetCode({
      email: 'not-an-email',
      code: '00000000',
      meta: meta(),
    });

    expect(!result.ok && result.code).toBe('invalid_token');
  });
});

describe('createAuth startup checks', () => {
  const base = () => ({
    stores: memoryStores(manualClock()),
    password: { hasher: plainHasher(), breachCheck: false as const },
    secret: SECRET,
    mailer: recordingMailer(),
  });

  const build = (config: object) => () =>
    createAuth(config as AuthConfig<AuthUser, Record<string, never>, readonly AuthPlugin[]>);

  it('refuses a config missing a store, the hasher or the mailer', () => {
    const { stores } = base();

    expect(build({ ...base(), stores: { ...stores, counters: undefined } })).toThrow(
      /stores\.users, stores\.sessions/u,
    );

    expect(build({ ...base(), stores: undefined })).toThrow(/stores\.users/u);
    expect(build({ ...base(), password: {} })).toThrow(/password\.hasher is required/u);
    expect(build({ ...base(), mailer: undefined })).toThrow(/mailer is required/u);

    expect(
      build({
        ...base(),
        urls: { resetPassword: (token: string) => `https://app.example/r#${token}` },
      }),
    ).not.toThrow();
  });

  it('accepts a later password after a refused one', async () => {
    const env = setup();
    const { session } = await env.signedInUser(EMAIL);

    const short = await env.auth.changePassword({
      session,
      currentPassword: PASSWORD,
      newPassword: 'short',
      meta: meta(),
    });

    const changed = await env.auth.changePassword({
      session,
      currentPassword: PASSWORD,
      newPassword: NEW_PASSWORD,
      meta: meta(),
    });

    expect(!short.ok && short.code).toBe('weak_password');
    expect(changed.ok).toBe(true);
  });
});
