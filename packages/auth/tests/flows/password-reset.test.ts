import { describe, expect, it } from 'vitest';
import { refuse, type PasswordResetJob } from '../../src';
import { meta, NEW_PASSWORD, PASSWORD, setup } from './setup';

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
  it('answers the same for known and unknown addresses and mails only the known one', async () => {
    const t = queued();
    await t.signedInUser(EMAIL);
    const known = await t.auth.requestPasswordReset({ email: EMAIL, meta: meta() });
    const unknown = await t.auth.requestPasswordReset({ email: 'ghost@example.com', meta: meta() });
    expect(known).toEqual(unknown);
    expect(t.jobs).toHaveLength(2);
    await t.drain();
    expect(t.mailer.sent.filter((m) => m.type === 'password-reset').map((m) => m.to)).toEqual([
      EMAIL,
    ]);
    expect(t.audit.events.find((e) => e.type === 'password.reset_request_ignored')?.reason).toBe(
      'unknown_user',
    );
  });

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

  it('sets the password, ends every session, mails the owner and marks the address verified', async () => {
    const t = queued();
    const { token, session } = await t.signedInUser(EMAIL);
    const link = await linkFor(t);
    expect(
      await t.auth.resetPassword({ token: link, password: NEW_PASSWORD, meta: meta() }),
    ).toEqual({ ok: true, value: undefined });
    expect(await t.sessionOf(token)).toBeNull();
    expect(t.mailer.last('password-changed')?.to).toBe(EMAIL);
    expect((await t.stores.users.findById(session.userId))?.emailVerified).toBe(true);
    expect((await t.auth.login({ email: EMAIL, password: PASSWORD, meta: meta() })).ok).toBe(false);
    expect((await t.auth.login({ email: EMAIL, password: NEW_PASSWORD, meta: meta() })).ok).toBe(
      true,
    );
  });

  it('leaves verification alone when markEmailVerified is off', async () => {
    const t = queued({ passwordReset: { markEmailVerified: false } });
    const { session } = await t.signedInUser(EMAIL);
    await t.auth.resetPassword({ token: await linkFor(t), password: NEW_PASSWORD, meta: meta() });
    expect((await t.stores.users.findById(session.userId))?.emailVerified).toBe(false);
  });

  it("ends a squatter's session when the mailbox owner resets (account pre-hijacking)", async () => {
    const t = queued();
    const squatter = await t.signedInUser('victim@example.com');
    await requestAndDrain(t, 'victim@example.com');
    await t.auth.resetPassword({
      token: tokenOf(t.mailer.last('password-reset')?.url),
      password: NEW_PASSWORD,
      meta: meta(),
    });
    expect(await t.sessionOf(squatter.token)).toBeNull();
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

  it('lets exactly one of two concurrent resets win', async () => {
    const t = queued();
    await t.signedInUser(EMAIL);
    const link = await linkFor(t);
    const results = await Promise.all([
      t.auth.resetPassword({ token: link, password: NEW_PASSWORD, meta: meta() }),
      t.auth.resetPassword({ token: link, password: 'yet another passphrase', meta: meta() }),
    ]);
    expect(results.filter((r) => r.ok)).toHaveLength(1);
  });

  it('refuses an expired link and a replayed one', async () => {
    const t = queued();
    await t.signedInUser(EMAIL);
    const link = await linkFor(t);
    t.clock.advance(3_600_000);
    expect(
      (await t.auth.resetPassword({ token: link, password: NEW_PASSWORD, meta: meta() })).ok,
    ).toBe(false);
    const fresh = await linkFor(t);
    await t.auth.resetPassword({ token: fresh, password: NEW_PASSWORD, meta: meta() });
    const replay = await t.auth.resetPassword({
      token: fresh,
      password: NEW_PASSWORD,
      meta: meta(),
    });
    expect(!replay.ok && replay.code).toBe('invalid_token');
  });

  it('lifts the lockout, since the mailbox was proved', async () => {
    const t = queued();
    await t.signedInUser(EMAIL);
    for (let i = 0; i < 11; i++)
      await t.auth.login({
        email: EMAIL,
        password: 'wrong passphrase!',
        meta: meta(`192.0.2.${i}`),
      });
    await t.auth.resetPassword({ token: await linkFor(t), password: NEW_PASSWORD, meta: meta() });
    expect((await t.auth.login({ email: EMAIL, password: NEW_PASSWORD, meta: meta() })).ok).toBe(
      true,
    );
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

  it('answers wrong codes and unknown addresses alike and caps attempts at 5', async () => {
    const t = queued({ passwordReset: { kind: 'code' } });
    await t.signedInUser(EMAIL);
    const code = await codeFor(t);
    const wrong = code === '00000000' ? '11111111' : '00000000';
    const ghost = await t.auth.verifyPasswordResetCode({
      email: 'ghost@example.com',
      code,
      meta: meta(),
    });
    expect(!ghost.ok && ghost.code).toBe('invalid_token');
    for (let i = 0; i < 5; i++) {
      const miss = await t.auth.verifyPasswordResetCode({
        email: EMAIL,
        code: wrong,
        meta: meta(`192.0.2.${i}`),
      });
      expect(!miss.ok && miss.code).toBe('invalid_token');
    }
    expect((await t.auth.verifyPasswordResetCode({ email: EMAIL, code, meta: meta() })).ok).toBe(
      false,
    );
  });

  it('counts guesses per address across IPs even with no code outstanding', async () => {
    const t = queued({ passwordReset: { kind: 'code' } });
    await t.signedInUser(EMAIL);
    // Sampling before any code exists, from five networks.
    for (let i = 0; i < 5; i++)
      await t.auth.verifyPasswordResetCode({
        email: EMAIL,
        code: '12345678',
        meta: meta(`192.0.2.${i}`),
      });
    const code = await codeFor(t);
    const blocked = await t.auth.verifyPasswordResetCode({
      email: EMAIL,
      code,
      meta: meta('198.51.100.1'),
    });
    expect(!blocked.ok && blocked.code).toBe('rate_limited');
    const ghost = await t.auth.verifyPasswordResetCode({
      email: 'ghost@example.com',
      code,
      meta: meta('198.51.100.2'),
    });
    expect(!ghost.ok && ghost.code).toBe('invalid_token');
    t.clock.advance(15 * 60_000);
    const fresh = await codeFor(t);
    expect(
      (
        await t.auth.verifyPasswordResetCode({
          email: EMAIL,
          code: fresh,
          meta: meta('198.51.100.1'),
        })
      ).ok,
    ).toBe(true);
  });

  it('refuses a raw code where a ticket is expected', async () => {
    const t = queued({ passwordReset: { kind: 'code' } });
    await t.signedInUser(EMAIL);
    const code = await codeFor(t);
    expect(
      (await t.auth.resetPassword({ token: code, password: NEW_PASSWORD, meta: meta() })).ok,
    ).toBe(false);
  });
});
