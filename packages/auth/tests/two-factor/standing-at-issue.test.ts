// `enforcementStanding: 'at-issue'`: a session issued unrestricted is stamped
// and validates without a read; every other session is read live. The
// changes that could restrict a stamped session are in attack A113.
import { describe, expect, it } from 'vitest';

import { AuthConfigError, type AuthUser } from '../../src';
import { stampIsOurs } from '../../src/plugins/two-factor/enforcement';
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
  it('reads the factor, the user and the policy on every request, stamps nothing, and still refreshes', async () => {
    const t = app(undefined);
    const { token, session } = await t.signedIn();

    expect(await t.validate(token)).toEqual({
      ok: true,
      standing: null,
      reads: { factor: 1, user: 1, policy: 1 },
    });

    expect(session.attributes).toEqual({});

    // A stamp from an earlier spell under 'at-issue' must not come back: it revokes here too.
    expect(await t.auth.twoFactor.refreshStanding({ userId: session.userId })).toEqual({
      ok: true,
      value: { revoked: true },
    });

    expect((await t.validate(token)).ok).toBe(false);
  });

  it('refreshes nothing without enforcement', async () => {
    const t = twoFactorApp();
    const { token, session } = await t.signedIn();

    expect(await t.auth.twoFactor.refreshStanding({ userId: session.userId })).toEqual({
      ok: true,
      value: { revoked: false },
    });

    expect(await t.sessionOf(token)).not.toBeNull();
  });
});

describe("'at-issue': maxAge", () => {
  const long = { session: { idleTimeout: '3d', absoluteTtl: '7d' } } as never;

  it('reads a stamped session live once the stamp is maxAge old', async () => {
    const t = app({ mode: 'at-issue', maxAge: '2h' }, { required: false }, long);
    const { token } = await t.signedIn();

    t.clock.advance(2 * 3600_000 - 1);
    expect((await t.validate(token)).reads).toEqual(NO_READS);

    t.clock.advance(1);
    expect((await t.validate(token)).reads).toEqual({ factor: 1, user: 1, policy: 1 });
  });

  it('keeps a stamp for a day by default', async () => {
    const t = app('at-issue', { required: false }, long);
    const { token } = await t.signedIn();

    t.clock.advance(24 * 3600_000 - 1);
    expect((await t.validate(token)).reads).toEqual(NO_READS);

    t.clock.advance(1);
    expect((await t.validate(token)).reads.policy).toBe(1);
  });
});

describe('enforcementStanding options', () => {
  it('needs enforcement, and refuses anything but the documented shapes', () => {
    expect(() => twoFactorApp({ enforcementStanding: 'at-issue' })).toThrow(
      'twoFactor: enforcementStanding needs enforcement',
    );

    for (const value of [
      'sometimes',
      true,
      { mode: 'later' },
      { mode: 'at-issue', version: '' },
      { mode: 'at-issue', version: 1 },
      { mode: 'at-issue', maxAge: 0 },
      { mode: 'at-issue', maxAge: '31d' },
      { mode: 'at-issue', maxAge: 'soon' },
    ])
      expect(() =>
        twoFactorApp({
          enforcement: () => ({ required: false }),
          enforcementStanding: value as never,
        }),
      ).toThrow(AuthConfigError);

    for (const value of [{ mode: 'at-issue' }, { mode: 'at-issue', version: 'v2', maxAge: '30d' }])
      expect(() =>
        twoFactorApp({
          enforcement: () => ({ required: false }),
          enforcementStanding: value as never,
        }),
      ).not.toThrow();
  });
});

describe('the session attribute schema at startup', () => {
  const schema = (parse: (value: unknown) => unknown) =>
    ({ session: { attributes: { parse } } }) as never;

  it("refuses a schema that refuses the stamp under 'at-issue'", () => {
    const strict = (value: unknown) => {
      if (Object.keys(value as object).length > 0) throw new Error('unknown key');

      return {};
    };

    expect(() => app('at-issue', { required: false }, schema(strict))).toThrow(
      'twoFactor: enforcementStanding',
    );

    expect(() => app(undefined, { required: false }, schema(strict))).not.toThrow();
  });

  it('only warns about a schema that drops the stamp', () => {
    const warnings: string[] = [];

    const logger = {
      warn: (message: string) => void warnings.push(message),
      error: () => undefined,
    };

    expect(() =>
      app('at-issue', { required: false }, { ...(schema(() => ({})) as object), logger } as never),
    ).not.toThrow();

    expect(warnings.some((w) => w.includes('drops twoFactorStanding'))).toBe(true);
  });

  it('cannot probe a schema with required keys of its own, and leaves it alone', () => {
    const needsOrg = (value: unknown) => {
      if (!(value as { org?: unknown }).org) throw new Error('org required');

      return value;
    };

    expect(() => app('at-issue', { required: false }, schema(needsOrg))).not.toThrow();
  });
});

describe('stampIsOurs', () => {
  it('reads attributes a schema turned into something other than an object as carrying no stamp', () => {
    const user = { id: 'u1' } as AuthUser;

    expect(stampIsOurs(user, null)).toBe(true);
    expect(stampIsOurs(user, 'attributes')).toBe(true);
    expect(stampIsOurs(user, { twoFactorStanding: 'anything' })).toBe(false);
  });
});
