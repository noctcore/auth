// `enforcementStanding: 'at-issue'`: a session issued unrestricted is stamped
// and validates without a read; every other session is read live. The
// changes that could restrict a stamped session are in attack A113.
import { describe, expect, it } from 'vitest';

import { AuthConfigError } from '../../src';
import { meta, standingApp as app, twoFactorApp } from './setup';

const MINUTE = 60_000;

const NO_READS = { factor: 0, user: 0, policy: 0 };

describe("'at-issue': sessions that skip the reads", () => {
  it('validates a session issued with no requirement without a factor or policy read', async () => {
    const t = app('at-issue');
    const { token } = await t.signedIn();

    expect(await t.validate(token)).toEqual({ ok: true, standing: null, reads: NO_READS });
  });

  it('validates a session of a user with a confirmed factor without a read', async () => {
    const t = app('at-issue', { required: true });
    const { secret } = await t.enrolled();
    const { token } = await t.passed(secret);

    expect(await t.validate(token)).toEqual({ ok: true, standing: null, reads: NO_READS });
  });
});

describe("'at-issue': sessions that are read live", () => {
  it('frees an enrollment-only session on the request after the user confirms a factor', async () => {
    const t = app('at-issue', { required: true });
    const { token, session } = await t.signedIn();

    expect(await t.validate(token)).toMatchObject({
      standing: { state: 'enrollment-only' },
      reads: { factor: 1, user: 1, policy: 1 },
    });

    const started = await t.auth.twoFactor.enroll({ session, meta: meta() });

    if (!started.ok) throw new Error(started.reason);

    await t.auth.twoFactor.confirmEnrollment({
      session,
      code: t.codeFor(started.value.secret),
      meta: meta(),
    });

    expect(await t.validate(token)).toMatchObject({ ok: true, standing: null });
  });

  it('reads a grace session live: it closes at the grace end and frees when the policy lifts', async () => {
    const t = app('at-issue');

    t.policy.current = { required: true, graceEndsAt: t.clock.now() + 10 * MINUTE };

    const { token } = await t.signedIn();

    expect((await t.validate(token)).standing).toMatchObject({ state: 'grace' });

    t.clock.advance(10 * MINUTE);

    expect((await t.validate(token)).standing).toEqual({ state: 'enrollment-only' });

    t.policy.current = { required: false };

    expect(await t.validate(token)).toMatchObject({ ok: true, standing: null });
  });
});

describe("'live' (the default)", () => {
  it('reads the factor, the user and the policy on every request, and stamps nothing', async () => {
    const t = app(undefined);
    const { token, session } = await t.signedIn();

    expect(await t.validate(token)).toEqual({
      ok: true,
      standing: null,
      reads: { factor: 1, user: 1, policy: 1 },
    });

    expect(session.attributes).toEqual({});

    expect(await t.auth.twoFactor.refreshStanding({ userId: session.userId })).toEqual({
      ok: true,
      value: { revoked: false },
    });

    expect((await t.validate(token)).ok).toBe(true);
  });
});

describe('enforcementStanding options', () => {
  it('needs enforcement, and refuses anything but the documented shapes', () => {
    expect(() => twoFactorApp({ enforcementStanding: 'at-issue' })).toThrow(
      'twoFactor: enforcementStanding needs enforcement',
    );

    for (const value of [
      'sometimes',
      { mode: 'at-issue' },
      { mode: 'at-issue', version: '' },
      true,
    ])
      expect(() =>
        twoFactorApp({
          enforcement: () => ({ required: false }),
          enforcementStanding: value as never,
        }),
      ).toThrow(AuthConfigError);
  });
});
