import { describe, expect, it } from 'vitest';

import { refuse } from '../../src';

import { EMAIL, meta, PASSWORD, twoFactorApp, unknownToken } from './setup';

describe('two-factor enrollment', () => {
  it('returns a base32 secret and an otpauth URI, and stores only the ciphertext, pending', async () => {
    const t = twoFactorApp();
    const { session } = await t.signedIn();
    const started = await t.auth.twoFactor.enroll({ session, meta: meta() });

    if (!started.ok) throw new Error(started.reason);

    expect(started.value.secret).toMatch(/^[A-Z2-7]{32}$/u);

    expect(started.value.uri).toBe(
      `otpauth://totp/Acme:ada%40example.com?secret=${started.value.secret}&issuer=Acme&algorithm=SHA1&digits=6&period=30`,
    );

    expect(started.value.expiresAt).toBe(t.clock.now() + 10 * 60_000);

    const stored = await t.store.findFactor(session.userId);

    expect(stored).toMatchObject({ confirmed: false, lastStep: -1, createdAt: t.clock.now() });
    expect(stored?.secret.startsWith('sealed:')).toBe(true);
    expect(stored?.secret).not.toContain(started.value.secret);
    expect(t.audit.types()).toContain('two_factor.enrollment_started');
  });

  it('does not guard the login until a code confirms the secret', async () => {
    const t = twoFactorApp();
    const { session } = await t.signedIn();

    await t.auth.twoFactor.enroll({ session, meta: meta() });

    const login = await t.auth.login({
      email: EMAIL,
      password: 'correct horse battery',
      meta: meta(),
    });

    expect(login.ok && login.value.kind).toBe('session');
  });

  it('confirms with a code, returns ten recovery codes, mails the owner and records a step-up', async () => {
    const t = twoFactorApp();
    const { session } = await t.signedIn();
    const started = await t.auth.twoFactor.enroll({ session, meta: meta() });

    if (!started.ok) throw new Error(started.reason);

    const code = t.codeFor(started.value.secret);
    const confirmed = await t.auth.twoFactor.confirmEnrollment({ session, code, meta: meta() });

    if (!confirmed.ok) throw new Error(confirmed.reason);

    expect(confirmed.value.session).toBeNull();
    expect(confirmed.value.recoveryCodes).toHaveLength(10);
    expect(new Set(confirmed.value.recoveryCodes).size).toBe(10);

    for (const recovery of confirmed.value.recoveryCodes)
      expect(recovery).toMatch(/^[0-9a-hjkmnp-tv-z]{5}-[0-9a-hjkmnp-tv-z]{5}$/u);

    const factor = await t.store.findFactor(session.userId);

    expect(factor?.confirmed).toBe(true);
    expect(await t.store.countRecoveryCodes(session.userId)).toBe(10);
    expect(await t.auth.twoFactor.requireStepUp(session)).toEqual({ ok: true, value: undefined });

    await Promise.resolve();

    expect(t.mailer.last('two-factor-enabled')).toMatchObject({
      to: EMAIL,
      userId: session.userId,
    });

    expect(t.audit.types()).toEqual(
      expect.arrayContaining(['two_factor.enabled', 'two_factor.recovery_codes_generated']),
    );
  });

  it('spends the confirming code: it cannot also pass the next challenge', async () => {
    const t = twoFactorApp();
    const { session } = await t.signedIn();
    const started = await t.auth.twoFactor.enroll({ session, meta: meta() });

    if (!started.ok) throw new Error(started.reason);

    const code = t.codeFor(started.value.secret);

    await t.auth.twoFactor.confirmEnrollment({ session, code, meta: meta() });

    const { challenge } = await t.challenged();

    const again = await t.auth.twoFactor.verifyChallenge({
      challenge,
      proof: { kind: 'totp', code },
      meta: meta(),
    });

    expect(!again.ok && again.reason).toBe('code_replayed');
  });

  it('can end every other session and re-issue the current one', async () => {
    const t = twoFactorApp();
    const other = await t.signedIn();

    const login = await t.auth.login({
      email: EMAIL,
      password: 'correct horse battery',
      meta: meta(),
    });

    if (!login.ok || login.value.kind !== 'session') throw new Error('login');

    const session = login.value.session.session;
    const started = await t.auth.twoFactor.enroll({ session, meta: meta() });

    if (!started.ok) throw new Error(started.reason);

    const confirmed = await t.auth.twoFactor.confirmEnrollment({
      session,
      code: t.codeFor(started.value.secret),
      revokeOtherSessions: true,
      meta: meta(),
    });

    if (!confirmed.ok) throw new Error(confirmed.reason);

    const reissued = confirmed.value.session;

    expect(reissued).not.toBeNull();
    expect(await t.sessionOf(other.token)).toBeNull();
    expect(await t.sessionOf(login.value.session.token)).toBeNull();
    expect(await t.sessionOf(reissued?.token ?? '')).not.toBeNull();
    expect(reissued?.session.authenticatedAt).toBe(session.authenticatedAt);

    expect(await t.auth.twoFactor.requireStepUp(reissued?.session ?? session)).toEqual({
      ok: true,
      value: undefined,
    });
  });

  it('needs a fresh credential proof to start and to confirm', async () => {
    const t = twoFactorApp();
    const { session } = await t.signedIn();

    t.clock.advance(11 * 60_000);

    const started = await t.auth.twoFactor.enroll({ session, meta: meta() });

    expect(!started.ok && started.code).toBe('fresh_auth_required');

    const confirmed = await t.auth.twoFactor.confirmEnrollment({
      session,
      code: '123456',
      meta: meta(),
    });

    expect(!confirmed.ok && confirmed.code).toBe('fresh_auth_required');
  });

  it('refuses to enroll over a confirmed factor', async () => {
    const t = twoFactorApp();
    const { session } = await t.enrolled();
    const again = await t.auth.twoFactor.enroll({ session, meta: meta() });

    expect(again).toMatchObject({ ok: false, code: 'forbidden', reason: 'factor_active' });
  });

  it('refuses when a factor was confirmed between the check and the write', async () => {
    const t = twoFactorApp();
    const { session } = await t.signedIn();

    t.store.findFactor = async () => null;
    t.store.putPendingFactor = async () => false;

    const started = await t.auth.twoFactor.enroll({ session, meta: meta() });

    expect(started).toMatchObject({ ok: false, code: 'forbidden', reason: 'factor_active' });
  });

  it('answers session_expired when the user is gone', async () => {
    const t = twoFactorApp();
    const { session } = await t.signedIn();

    await t.stores.users.softDelete(session.userId);

    const started = await t.auth.twoFactor.enroll({ session, meta: meta() });

    expect(!started.ok && started.code).toBe('session_expired');
  });

  it('refuses a wrong code, a code for a replaced secret and a secret left pending too long', async () => {
    const t = twoFactorApp();
    const { session } = await t.signedIn();
    const first = await t.auth.twoFactor.enroll({ session, meta: meta() });
    const second = await t.auth.twoFactor.enroll({ session, meta: meta() });

    if (!first.ok || !second.ok) throw new Error('enroll');

    const confirm = (code: string) =>
      t.auth.twoFactor.confirmEnrollment({ session, code, meta: meta() });

    const wrong = await confirm(t.codeFor(second.value.secret) === '000000' ? '111111' : '000000');

    expect(wrong).toMatchObject({ ok: false, code: 'invalid_second_factor', reason: 'wrong_code' });
    expect((await confirm(t.codeFor(first.value.secret))).ok).toBe(false);

    t.clock.advance(10 * 60_000);

    const stale = await confirm(t.codeFor(second.value.secret));

    expect(!stale.ok && stale.reason).toBe('no_pending_enrollment');
  });

  it('refuses a code when another enrollment replaced the secret after it was read', async () => {
    const t = twoFactorApp();
    const { session } = await t.signedIn();
    const started = await t.auth.twoFactor.enroll({ session, meta: meta() });

    if (!started.ok) throw new Error(started.reason);

    t.store.confirmFactor = async () => false;

    const confirmed = await t.auth.twoFactor.confirmEnrollment({
      session,
      code: t.codeFor(started.value.secret),
      meta: meta(),
    });

    expect(!confirmed.ok && confirmed.reason).toBe('enrollment_race');
  });

  it('answers session_expired when the user disappears before the re-issue', async () => {
    const t = twoFactorApp();
    const { session } = await t.signedIn();
    const started = await t.auth.twoFactor.enroll({ session, meta: meta() });

    if (!started.ok) throw new Error(started.reason);

    const code = t.codeFor(started.value.secret);

    // The enabled notice looks the user up after the confirm; the re-issue next.
    const findById = t.stores.users.findById.bind(t.stores.users);
    let lookups = 0;

    t.stores.users.findById = async (id) => (++lookups > 1 ? null : findById(id));

    const confirmed = await t.auth.twoFactor.confirmEnrollment({
      session,
      code,
      revokeOtherSessions: true,
      meta: meta(),
    });

    expect(!confirmed.ok && confirmed.code).toBe('session_expired');
  });

  it('passes the refusal of the re-issued session through', async () => {
    const t = twoFactorApp(
      {},
      {
        hooks: {
          beforeSessionCreate: ({ via }) =>
            via === 'second-factor' ? refuse('app_says_no', 'forbidden') : undefined,
        },
      },
    );

    const { session } = await t.signedIn();
    const started = await t.auth.twoFactor.enroll({ session, meta: meta() });

    if (!started.ok) throw new Error(started.reason);

    const confirmed = await t.auth.twoFactor.confirmEnrollment({
      session,
      code: t.codeFor(started.value.secret),
      revokeOtherSessions: true,
      meta: meta(),
    });

    expect(confirmed).toMatchObject({ ok: false, code: 'forbidden', reason: 'app_says_no' });
  });

  it('enrolls through an enrollment challenge and refuses a bad one', async () => {
    const t = twoFactorApp({ required: () => true });

    await t.auth.register({ email: EMAIL, password: 'correct horse battery', meta: meta() });

    const { challenge, methods } = await t.challenged();

    expect(methods).toEqual(['enroll']);

    const started = await t.auth.twoFactor.enroll({ challenge, meta: meta() });

    expect(started.ok).toBe(true);

    const unknown = await t.auth.twoFactor.enroll({ challenge: unknownToken(), meta: meta() });

    expect(unknown).toMatchObject({ ok: false, code: 'invalid_token', reason: 'enroll_challenge' });

    const foreign = await t.auth.twoFactor.enroll({
      challenge,
      meta: { ...meta(), userAgent: 'another browser' },
    });

    expect(!foreign.ok && foreign.code).toBe('invalid_token');
  });

  it('refuses a verify challenge as an enrollment challenge', async () => {
    const t = twoFactorApp();

    await t.enrolled();

    const { challenge } = await t.challenged();
    const started = await t.auth.twoFactor.enroll({ challenge, meta: meta() });

    expect(!started.ok && started.reason).toBe('enroll_challenge');
  });

  it('rate limits enrollment per IP', async () => {
    const t = twoFactorApp({ perIp: { limit: 1, window: '1m' } });
    const { session } = await t.signedIn();

    await t.auth.twoFactor.enroll({ session, meta: meta() });

    const limited = await t.auth.twoFactor.enroll({ session, meta: meta() });

    const confirm = await t.auth.twoFactor.confirmEnrollment({
      session,
      code: '123456',
      meta: meta(),
    });

    expect(!limited.ok && limited.code).toBe('rate_limited');
    expect(!confirm.ok && confirm.code).toBe('rate_limited');
    expect(t.audit.events.filter((e) => e.type === 'rate_limit.exceeded')).toHaveLength(1);
  });

  it('activates the factor without a mail when the user vanished before the confirmation', async () => {
    const t = twoFactorApp();
    const { session } = await t.signedIn();
    const started = await t.auth.twoFactor.enroll({ session, meta: meta() });

    if (!started.ok) throw new Error(started.reason);

    const findById = t.stores.users.findById.bind(t.stores.users);

    t.stores.users.findById = async (id) => (id === session.userId ? null : findById(id));

    const confirmed = await t.auth.twoFactor.confirmEnrollment({
      session,
      code: t.codeFor(started.value.secret),
      meta: meta(),
    });

    expect(confirmed.ok).toBe(true);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(t.mailer.last('two-factor-enabled')).toBeUndefined();
  });

  it('binds a challenge to a client without a user agent too', async () => {
    const t = twoFactorApp();
    const { secret } = await t.enrolled();

    const login = await t.auth.login({
      email: EMAIL,
      password: PASSWORD,
      meta: { ip: '203.0.113.9', origin: 'https://app.example' },
    });

    if (!login.ok || login.value.kind !== 'challenge') throw new Error('expected a challenge');

    const anonymous = await t.auth.twoFactor.verifyChallenge({
      challenge: login.value.challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      meta: { ip: '203.0.113.9', origin: 'https://app.example' },
    });

    expect(anonymous.ok).toBe(true);
  });
});
