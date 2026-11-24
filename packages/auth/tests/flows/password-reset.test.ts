import { describe, expect, it } from 'vitest';
import { refuse, type PasswordResetJob } from '../../src';
import { meta, NEW_PASSWORD, settled, setup } from './setup';

const EMAIL = 'ada@example.com';
const tokenOf = (url: string | undefined) => (url ?? '').split('#')[1] ?? '';

function queued(overrides: Parameters<typeof setup>[0] = {}) {
  const jobs: PasswordResetJob[] = [];

  const t = setup({
    ...overrides,
    passwordReset: { enqueue: async (job) => void jobs.push(job), ...overrides.passwordReset },
  });

  async function drain() {
    while (jobs.length) await t.auth.jobs.processPasswordReset(jobs.shift() as PasswordResetJob);
  }

  return { ...t, jobs, drain };
}

type Queued = ReturnType<typeof queued>;

async function requestAndDrain(t: Queued, email = EMAIL) {
  await t.auth.requestPasswordReset({ email, meta: meta() });
  await t.drain();
}

describe('password reset request', () => {
  it('gives repeated requests within a minute the same dedupe key', async () => {
    const t = queued();

    await t.auth.requestPasswordReset({ email: EMAIL, meta: meta() });
    await t.auth.requestPasswordReset({ email: EMAIL, meta: meta() });
    expect(t.jobs[0]?.dedupeKey).toBe(t.jobs[1]?.dedupeKey);
  });

  it('caps reset mails per account at 3 an hour', async () => {
    const t = queued();

    await t.signedInUser(EMAIL);

    for (let i = 0; i < 5; i++)
      await t.auth.requestPasswordReset({ email: EMAIL, meta: meta(`192.0.2.${i}`) });

    await t.drain();
    expect(t.mailer.sent.filter((m) => m.type === 'password-reset')).toHaveLength(3);
  });

  it('runs detached in-process without a queue', async () => {
    const t = setup();

    await t.signedInUser(EMAIL);
    await t.auth.requestPasswordReset({ email: EMAIL, meta: meta() });
    await new Promise((r) => setTimeout(r, 0));
    expect(t.mailer.last('password-reset')).toBeDefined();
  });

  it('stays silent when a hook refuses the account', async () => {
    const t = queued({ hooks: { beforePasswordResetRequest: () => refuse('portal_account') } });

    await t.signedInUser(EMAIL);
    await requestAndDrain(t);
    expect(t.mailer.last('password-reset')).toBeUndefined();
  });
});

describe('password reset by link', () => {
  async function linkFor(t: Queued) {
    await requestAndDrain(t);

    return tokenOf(t.mailer.last('password-reset')?.url);
  }

  it('leaves verification alone when markEmailVerified is off', async () => {
    const t = queued({ passwordReset: { markEmailVerified: false } });
    const { session } = await t.signedInUser(EMAIL);

    await t.auth.resetPassword({ token: await linkFor(t), password: NEW_PASSWORD, meta: meta() });
    expect((await t.stores.users.findById(session.userId))?.emailVerified).toBe(false);
  });

  it('does not burn the link on a password the policy refuses', async () => {
    const t = queued();

    await t.signedInUser(EMAIL);
    const link = await linkFor(t);
    const weak = await t.auth.resetPassword({ token: link, password: 'short', meta: meta() });

    expect(!weak.ok && weak.code).toBe('weak_password');

    expect(
      (await t.auth.resetPassword({ token: link, password: NEW_PASSWORD, meta: meta() })).ok,
    ).toBe(true);
  });

  it('asks the second-factor seam before applying the reset', async () => {
    const t = queued({
      hooks: {
        beforePasswordReset: ({ secondFactor }) =>
          secondFactor === '123456' ? undefined : refuse('totp_required', 'second_factor_required'),
      },
    });

    await t.signedInUser(EMAIL);
    const link = await linkFor(t);

    const missing = await t.auth.resetPassword({
      token: link,
      password: NEW_PASSWORD,
      meta: meta(),
    });

    expect(!missing.ok && missing.code).toBe('second_factor_required');

    expect(
      (
        await t.auth.resetPassword({
          token: link,
          password: NEW_PASSWORD,
          secondFactor: '123456',
          meta: meta(),
        })
      ).ok,
    ).toBe(true);
  });
});

describe('password reset by code', () => {
  async function codeFor(t: Queued) {
    await requestAndDrain(t);

    return t.mailer.last('password-reset-code')?.code ?? '';
  }

  it('exchanges a correct code for a ticket that resets the password', async () => {
    const t = queued({ passwordReset: { kind: 'code' } });

    await t.signedInUser(EMAIL);
    const code = await codeFor(t);
    const ticket = await t.auth.verifyPasswordResetCode({ email: EMAIL, code, meta: meta() });

    if (!ticket.ok) throw new Error(ticket.reason);

    // The code is spent: it cannot be exchanged twice.
    expect((await t.auth.verifyPasswordResetCode({ email: EMAIL, code, meta: meta() })).ok).toBe(
      false,
    );

    expect(
      (
        await t.auth.resetPassword({
          token: ticket.value.ticket,
          password: NEW_PASSWORD,
          meta: meta(),
        })
      ).ok,
    ).toBe(true);
  });
});

describe('the issued reset event', () => {
  const issued = (t: ReturnType<typeof setup>) =>
    t.audit.events.filter((e) => e.type === 'password.reset_issued');

  it('fires once per link issued on a queue, with the user and the request IP', async () => {
    const t = queued();
    const { session } = await t.signedInUser(EMAIL);

    await t.auth.requestPasswordReset({ email: EMAIL, meta: meta('198.51.100.9') });
    await t.drain();

    expect(issued(t)).toEqual([
      {
        type: 'password.reset_issued',
        userId: session.userId,
        data: { kind: 'link' },
        meta: { ip: '198.51.100.9', userAgent: 'vitest' },
      },
    ]);
  });

  it('fires for a code, and for a job run in-process', async () => {
    const t = setup({ passwordReset: { kind: 'code' } });
    const { session } = await t.signedInUser(EMAIL);

    await t.auth.requestPasswordReset({ email: EMAIL, meta: meta() });
    await settled();

    expect(issued(t)).toMatchObject([
      { userId: session.userId, data: { kind: 'code' }, meta: { ip: meta().ip } },
    ]);
  });

  it('stays out of every request that sends nothing', async () => {
    const t = queued({ hooks: { beforePasswordResetRequest: () => refuse('portal_account') } });

    await t.signedInUser(EMAIL);
    await requestAndDrain(t, 'nobody@example.com');
    await requestAndDrain(t);

    const limited = queued();

    await limited.signedInUser(EMAIL);

    for (let i = 0; i < 4; i++) await requestAndDrain(limited);

    expect(issued(t)).toEqual([]);
    expect(t.audit.types().filter((type) => type === 'password.reset_request_ignored')).toHaveLength(
      2,
    );

    expect(issued(limited)).toHaveLength(3);
    expect(limited.mailer.sent.filter((m) => m.type === 'password-reset')).toHaveLength(3);
  });
});

describe('the request meta on the reset mail', () => {
  it('carries the IP and user agent of the request through a queue', async () => {
    const t = queued();

    await t.signedInUser(EMAIL);
    await t.auth.requestPasswordReset({
      email: EMAIL,
      meta: { ip: '198.51.100.9', userAgent: 'Firefox/140' },
    });

    expect(t.jobs[0]).toMatchObject({ ip: '198.51.100.9', userAgent: 'Firefox/140' });

    await t.drain();

    expect(t.mailer.last('password-reset')?.meta).toEqual({
      ip: '198.51.100.9',
      userAgent: 'Firefox/140',
    });
  });

  it('carries the same for a code mailed in-process', async () => {
    const t = setup({ passwordReset: { kind: 'code' } });

    await t.signedInUser(EMAIL);
    await t.auth.requestPasswordReset({ email: EMAIL, meta: meta('198.51.100.9') });
    await settled();

    expect(t.mailer.last('password-reset-code')?.meta).toEqual({
      ip: '198.51.100.9',
      userAgent: 'vitest',
    });
  });

  it('carries only the IP for a job without a user agent, as jobs queued before it were', async () => {
    const t = queued();

    await t.signedInUser(EMAIL);
    await t.auth.requestPasswordReset({ email: EMAIL, meta: { ip: '198.51.100.9' } });

    expect(t.jobs[0]).not.toHaveProperty('userAgent');

    await t.drain();

    expect(t.mailer.last('password-reset')?.meta).toEqual({ ip: '198.51.100.9' });
  });

  it('carries the meta of the reset on its password-changed mail', async () => {
    const t = queued();

    await t.signedInUser(EMAIL);
    await requestAndDrain(t);

    const token = tokenOf(t.mailer.last('password-reset')?.url);

    await t.auth.resetPassword({ token, password: NEW_PASSWORD, meta: meta('192.0.2.44') });
    await settled();

    expect(t.mailer.last('password-changed')?.meta).toEqual({
      ip: '192.0.2.44',
      userAgent: 'vitest',
    });
  });
});
