import { describe, expect, it, vi } from 'vitest';
import { refuse, type PasswordResetJob } from '../../src';
import { meta, NEW_PASSWORD, settled, setup } from './setup';
import { changed, requestCode } from './email-change-support';
import { twoFactorApp } from '../two-factor/setup';
import { PURPOSE, RESET_PURPOSES } from '../../src/flows/settings';

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

    expect(
      t.audit.types().filter((type) => type === 'password.reset_request_ignored'),
    ).toHaveLength(2);

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

describe('inspecting a reset link', () => {
  async function linkFor(t: Queued) {
    await requestAndDrain(t);

    return tokenOf(t.mailer.last('password-reset')?.url);
  }

  it('answers a live link twice without spending it, and the reset still works', async () => {
    const t = queued();
    const { session } = await t.signedInUser(EMAIL);
    const token = await linkFor(t);
    const first = await t.auth.inspectPasswordReset({ token, meta: meta() });
    const second = await t.auth.inspectPasswordReset({ token, meta: meta() });

    expect(first).toEqual({
      ok: true,
      value: {
        userId: session.userId,
        email: EMAIL,
        expiresAt: t.clock.now() + 60 * 60_000,
        secondFactorRequired: false,
      },
    });

    expect(second).toEqual(first);

    // Only the id and the address: the link holder never sees the rest of the user.
    expect(first.ok && Object.keys(first.value).sort()).toEqual([
      'email',
      'expiresAt',
      'secondFactorRequired',
      'userId',
    ]);

    expect(t.audit.types().filter((type) => type === 'password.reset_inspected')).toHaveLength(2);

    expect((await t.auth.resetPassword({ token, password: NEW_PASSWORD, meta: meta() })).ok).toBe(
      true,
    );
  });

  it('answers unknown, expired and spent links the same, naming no account for an unknown one', async () => {
    const t = queued();

    await t.signedInUser(EMAIL);

    const spent = await linkFor(t);

    await t.auth.resetPassword({ token: spent, password: NEW_PASSWORD, meta: meta() });

    const expired = await linkFor(t);

    t.clock.advance(60 * 60_000);

    const before = t.audit.events.length;
    const unknown = await t.auth.inspectPasswordReset({ token: 'x'.repeat(43), meta: meta() });
    const unknownEvents = t.audit.events.slice(before);

    const answers = await Promise.all(
      [spent, expired].map((token) => t.auth.inspectPasswordReset({ token, meta: meta() })),
    );

    for (const answer of [unknown, ...answers])
      expect(!answer.ok && answer.code).toBe('invalid_token');

    expect(unknownEvents).toEqual([
      expect.objectContaining({ type: 'password.reset_inspect_failed', reason: 'unknown' }),
    ]);

    expect(unknownEvents[0]).not.toHaveProperty('userId');
    expect(t.mailer.sent.filter((m) => m.type === 'password-reset')).toHaveLength(2);
  });

  it('counts inspections and resets on the same door', async () => {
    const t = queued({ throttle: { doors: { 'password-reset': { limit: 3, window: '1m' } } } });

    await t.signedInUser(EMAIL);
    const token = await linkFor(t);

    await t.auth.inspectPasswordReset({ token, meta: meta() });
    await t.auth.inspectPasswordReset({ token, meta: meta() });

    expect((await t.auth.resetPassword({ token, password: NEW_PASSWORD, meta: meta() })).ok).toBe(
      true,
    );

    const fourth = await t.auth.inspectPasswordReset({ token, meta: meta() });

    expect(!fourth.ok && fourth.code).toBe('rate_limited');
  });

  it('answers a ticket in code mode, and refuses the raw code', async () => {
    const t = queued({ passwordReset: { kind: 'code' } });

    await t.signedInUser(EMAIL);
    await requestAndDrain(t);

    const code = t.mailer.last('password-reset-code')?.code ?? '';
    const raw = await t.auth.inspectPasswordReset({ token: code, meta: meta() });
    const ticket = await t.auth.verifyPasswordResetCode({ email: EMAIL, code, meta: meta() });

    if (!ticket.ok) throw new Error(ticket.reason);

    const inspected = await t.auth.inspectPasswordReset({
      token: ticket.value.ticket,
      meta: meta(),
    });

    expect(!raw.ok && raw.code).toBe('invalid_token');
    expect(inspected.ok && inspected.value.expiresAt).toBe(ticket.value.expiresAt);
  });

  it('runs no beforePasswordReset hook, and takes the requirement from the requirement hooks', async () => {
    const beforePasswordReset = vi.fn(() => undefined);

    const t = queued({
      hooks: {
        beforePasswordReset,
        passwordResetRequirements: [
          () => ({ secondFactor: false }),
          () => ({ secondFactor: true }),
        ],
      },
    });

    await t.signedInUser(EMAIL);

    const inspected = await t.auth.inspectPasswordReset({ token: await linkFor(t), meta: meta() });

    expect(inspected.ok && inspected.value.secondFactorRequired).toBe(true);
    expect(beforePasswordReset).not.toHaveBeenCalled();
  });

  it('answers a refusal from a requirement hook, as the reset would', async () => {
    const t = queued({
      hooks: { passwordResetRequirements: () => refuse('account_closed', 'invalid_token') },
    });

    await t.signedInUser(EMAIL);

    const inspected = await t.auth.inspectPasswordReset({ token: await linkFor(t), meta: meta() });

    expect(inspected).toMatchObject({ ok: false, code: 'invalid_token' });

    expect(t.audit.events.at(-1)).toMatchObject({
      type: 'password.reset_inspect_failed',
      reason: 'account_closed',
    });
  });

  it('says a second factor is required for an account with a confirmed factor', async () => {
    const t = twoFactorApp();

    await t.enrolled();
    await t.auth.requestPasswordReset({ email: EMAIL, meta: meta() });
    await settled();

    const token = tokenOf(t.mailer.last('password-reset')?.url);
    const inspected = await t.auth.inspectPasswordReset({ token, meta: meta() });

    await t.signedIn('grace@example.com');
    await t.auth.requestPasswordReset({ email: 'grace@example.com', meta: meta() });
    await settled();

    const plain = await t.auth.inspectPasswordReset({
      token: tokenOf(t.mailer.last('password-reset')?.url),
      meta: meta(),
    });

    expect(inspected.ok && inspected.value.secondFactorRequired).toBe(true);
    expect(plain.ok && plain.value.secondFactorRequired).toBe(false);
  });
});

describe('revoking an account reset tokens', () => {
  const revokedEvents = (t: ReturnType<typeof setup>) =>
    t.audit.events.filter((e) => e.type === 'password.reset_revoked');

  async function linkFor(t: Queued, email = EMAIL) {
    await requestAndDrain(t, email);

    return tokenOf(t.mailer.last('password-reset')?.url);
  }

  it('kills a link issued before it, at the inspection and at the reset', async () => {
    const t = queued();
    const { session } = await t.signedInUser(EMAIL);
    const token = await linkFor(t);

    expect(
      await t.auth.revokePasswordResets({ userId: session.userId, meta: meta('198.51.100.4') }),
    ).toEqual({ revoked: true });

    const inspected = await t.auth.inspectPasswordReset({ token, meta: meta() });
    const reset = await t.auth.resetPassword({ token, password: NEW_PASSWORD, meta: meta() });

    expect(!inspected.ok && inspected.code).toBe('invalid_token');
    expect(!reset.ok && reset.code).toBe('invalid_token');

    expect(revokedEvents(t)).toEqual([
      {
        type: 'password.reset_revoked',
        userId: session.userId,
        meta: { ip: '198.51.100.4', userAgent: 'vitest', origin: 'https://app.example' },
      },
    ]);

    expect(t.mailer.sent.filter((m) => m.type === 'password-reset')).toHaveLength(1);
  });

  it('kills a code and a ticket issued before it in code mode', async () => {
    const t = queued({ passwordReset: { kind: 'code' } });
    const { session } = await t.signedInUser(EMAIL);

    await requestAndDrain(t);

    const exchanged = await t.auth.verifyPasswordResetCode({
      email: EMAIL,
      code: t.mailer.last('password-reset-code')?.code ?? '',
      meta: meta(),
    });

    if (!exchanged.ok) throw new Error(exchanged.reason);

    // A second code, so a code and a ticket are both outstanding.
    await requestAndDrain(t);

    const code = t.mailer.last('password-reset-code')?.code ?? '';
    const { ticket } = exchanged.value;

    expect(await t.auth.revokePasswordResets({ userId: session.userId })).toEqual({
      revoked: true,
    });

    const verified = await t.auth.verifyPasswordResetCode({ email: EMAIL, code, meta: meta() });
    const inspected = await t.auth.inspectPasswordReset({ token: ticket, meta: meta() });

    const reset = await t.auth.resetPassword({
      token: ticket,
      password: NEW_PASSWORD,
      meta: meta(),
    });

    expect(!verified.ok && verified.code).toBe('invalid_token');
    expect(!inspected.ok && inspected.code).toBe('invalid_token');
    expect(!reset.ok && reset.code).toBe('invalid_token');
    expect(revokedEvents(t)).toMatchObject([{ userId: session.userId }]);
  });

  it('counts a ticket alone as something removed', async () => {
    const t = queued({ passwordReset: { kind: 'code' } });
    const { session } = await t.signedInUser(EMAIL);

    await requestAndDrain(t);

    const exchanged = await t.auth.verifyPasswordResetCode({
      email: EMAIL,
      code: t.mailer.last('password-reset-code')?.code ?? '',
      meta: meta(),
    });

    if (!exchanged.ok) throw new Error(exchanged.reason);

    expect(await t.auth.revokePasswordResets({ userId: session.userId })).toEqual({
      revoked: true,
    });

    expect(revokedEvents(t)).toHaveLength(1);
  });

  it('leaves a link issued after it working', async () => {
    const t = queued();
    const { session } = await t.signedInUser(EMAIL);

    await linkFor(t);
    await t.auth.revokePasswordResets({ userId: session.userId, meta: meta() });

    const token = await linkFor(t);

    expect((await t.auth.inspectPasswordReset({ token, meta: meta() })).ok).toBe(true);

    expect((await t.auth.resetPassword({ token, password: NEW_PASSWORD, meta: meta() })).ok).toBe(
      true,
    );
  });

  it('succeeds for an account with no reset token, emits nothing and mails nothing', async () => {
    const t = queued();
    const { session } = await t.signedInUser(EMAIL);
    const mailed = t.mailer.sent.length;

    expect(await t.auth.revokePasswordResets({ userId: session.userId, meta: meta() })).toEqual({
      revoked: false,
    });

    expect(await t.auth.revokePasswordResets({ userId: 'no-such-user' })).toEqual({
      revoked: false,
    });

    expect(revokedEvents(t)).toEqual([]);
    expect(t.mailer.sent).toHaveLength(mailed);
  });

  it('is idempotent: a second call removes nothing and emits nothing', async () => {
    const t = queued();
    const { session } = await t.signedInUser(EMAIL);

    await linkFor(t);
    await t.auth.revokePasswordResets({ userId: session.userId, meta: meta() });

    expect(await t.auth.revokePasswordResets({ userId: session.userId, meta: meta() })).toEqual({
      revoked: false,
    });

    expect(revokedEvents(t)).toHaveLength(1);
  });

  it('does not count an expired link as something removed', async () => {
    const t = queued();
    const { session } = await t.signedInUser(EMAIL);

    await linkFor(t);
    t.clock.advance(24 * 60 * 60_000);

    expect(await t.auth.revokePasswordResets({ userId: session.userId })).toEqual({
      revoked: false,
    });

    expect(revokedEvents(t)).toEqual([]);
  });

  it('leaves the reset tokens of other accounts alone', async () => {
    const t = queued();
    const { session } = await t.signedInUser(EMAIL);

    await t.signedInUser('grace@example.com');

    const theirs = await linkFor(t, 'grace@example.com');

    await linkFor(t);
    await t.auth.revokePasswordResets({ userId: session.userId });

    expect((await t.auth.inspectPasswordReset({ token: theirs, meta: meta() })).ok).toBe(true);
  });

  it('leaves a verification link of the account working', async () => {
    const t = queued({ emailVerification: { kind: 'link' } });
    const { session } = await t.signedInUser(EMAIL);
    const mail = t.mailer.last('verify-email');
    const token = tokenOf(mail?.type === 'verify-email' ? mail.url : undefined);

    await linkFor(t);
    await t.auth.revokePasswordResets({ userId: session.userId, meta: meta() });

    expect((await t.auth.verifyEmailLink({ token, session, meta: meta() })).ok).toBe(true);
  });

  it('leaves a pending email change of the account working', async () => {
    const t = queued();
    const { session } = await t.signedInUser(EMAIL);
    const code = await requestCode(t, session, 'grace@example.com');

    await linkFor(t);
    await t.auth.revokePasswordResets({ userId: session.userId, meta: meta() });

    expect((await t.auth.confirmEmailChangeCode({ session, code, meta: meta() })).ok).toBe(true);
  });

  it('leaves a revert link of the account working', async () => {
    const t = queued();
    const { session } = await t.signedInUser(EMAIL);
    const after = await changed(t, session, 'grace@example.com');

    await linkFor(t, 'grace@example.com');

    expect(await t.auth.revokePasswordResets({ userId: session.userId })).toEqual({
      revoked: true,
    });

    expect((await t.auth.revertEmailChange({ token: after.revert, meta: meta() })).ok).toBe(true);
  });

  it('removes only the reset purposes from the token store', async () => {
    const t = setup();
    const userId = 'user-1';
    const expiresAt = t.clock.now() + 60_000;
    const purposes = Object.values(PURPOSE);

    for (const purpose of purposes)
      await t.stores.tokens.put({
        purpose,
        userId,
        hash: purpose,
        expiresAt,
        attempts: 0,
        data: {},
      });

    expect(await t.auth.revokePasswordResets({ userId })).toEqual({ revoked: true });

    const left = await Promise.all(
      purposes.map(async (purpose) => [
        purpose,
        (await t.stores.tokens.findByUser(purpose, userId)) !== null,
      ]),
    );

    expect(Object.fromEntries(left)).toEqual(
      Object.fromEntries(purposes.map((p) => [p, !RESET_PURPOSES.includes(p)])),
    );
  });
});
