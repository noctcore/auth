// Enforcement with a grace period: the `enforcement` option, the grace and
// enrollment-only standings validation attaches, the live re-check on every
// request, the fail-closed policy and the sweep.
import { describe, expect, it, vi } from 'vitest';

import { AuthConfigError, type AuthUser, type Logger, type StoredSession } from '../../src';
import type { TwoFactorPolicy } from '../../src/plugins/two-factor';
import { EMAIL, meta, PASSWORD, twoFactorApp } from './setup';

const MINUTE = 60_000;

/** A fixed answer, or one per user (which may throw). */
type Policy = TwoFactorPolicy | ((user: AuthUser) => TwoFactorPolicy);

/** An app whose enforcement policy is whatever `policy.current` is now; counts the calls. */
function enforcedApp(initial: Policy = { required: false }, overrides = {}) {
  const policy = { current: initial, calls: 0 };
  const logged: { message: string; context: Record<string, unknown> | undefined }[] = [];

  const logger: Logger = {
    warn: () => undefined,
    error: (message, context) => void logged.push({ message, context }),
  };

  const t = twoFactorApp(
    {
      enforcement: ({ user }) => {
        policy.calls++;

        const current = policy.current;

        return typeof current === 'function' ? current(user) : current;
      },
    },
    { logger, ...overrides },
  );

  return { ...t, policy, logged };
}

const thrower = (): never => {
  throw new TypeError('policy for ada@example.com failed');
};

describe('enforcement options', () => {
  it('is off by default: validation attaches nothing and asks no policy', async () => {
    const t = twoFactorApp();
    const { token } = await t.signedIn();
    const validated = await t.auth.validateRequest({ token, meta: meta() });

    expect(validated.ok && 'twoFactor' in validated.value).toBe(false);
  });

  it('refuses required and enforcement together, and an enforcement that is not a function', () => {
    expect(() =>
      twoFactorApp({ required: () => true, enforcement: () => ({ required: true }) }),
    ).toThrow(AuthConfigError);

    expect(() => twoFactorApp({ enforcement: 'yes' as never })).toThrow(
      'twoFactor: enforcement must be a function',
    );
  });
});

describe('in the grace window', () => {
  it('signs in as usual and flags every validated session with the grace end', async () => {
    const t = enforcedApp();
    const graceEndsAt = new Date(t.clock.now() + 10 * MINUTE);

    t.policy.current = { required: true, graceEndsAt };

    const { token } = await t.signedIn();
    const validated = await t.auth.validateRequest({ token, meta: meta() });

    expect(validated).toMatchObject({
      ok: true,
      value: { twoFactor: { state: 'grace', graceEndsAt: graceEndsAt.getTime() } },
    });

    const status = await t.auth.twoFactor.status(validated.ok ? validated.value : ({} as never));

    expect(status).toMatchObject({
      ok: true,
      value: {
        required: true,
        enforcement: { state: 'grace', graceEndsAt: graceEndsAt.getTime() },
      },
    });
  });

  it('takes the grace end as a number too', async () => {
    const t = enforcedApp();
    const graceEndsAt = t.clock.now() + 5 * MINUTE;

    t.policy.current = { required: true, graceEndsAt };

    const { token } = await t.signedIn();

    expect(await t.sessionOf(token)).toMatchObject({
      twoFactor: { state: 'grace', graceEndsAt },
    });
  });
});

describe('after the grace window', () => {
  it('signs in to an enrollment-only session, never a challenge', async () => {
    const t = enforcedApp({ required: true });

    await t.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });

    const login = await t.auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    if (!login.ok || login.value.kind !== 'session') throw new Error('expected a session');

    expect(await t.sessionOf(login.value.session.token)).toMatchObject({
      twoFactor: { state: 'enrollment-only' },
    });
  });

  it('turns a grace session enrollment-only when the window closes, without a new sign-in', async () => {
    const t = enforcedApp();

    t.policy.current = { required: true, graceEndsAt: t.clock.now() + 10 * MINUTE };

    const { token } = await t.signedIn();

    expect((await t.sessionOf(token))?.twoFactor?.state).toBe('grace');

    t.clock.advance(10 * MINUTE);

    expect((await t.sessionOf(token))?.twoFactor).toEqual({ state: 'enrollment-only' });
  });

  it('lets the enrollment-only session enroll, and drops the standing once the factor is on', async () => {
    const t = enforcedApp({ required: true });
    const { token, session } = await t.signedIn();
    const started = await t.auth.twoFactor.enroll({ session, meta: meta() });

    if (!started.ok) throw new Error(started.reason);

    // A pending factor is not a factor: still enrollment-only.
    expect((await t.sessionOf(token))?.twoFactor?.state).toBe('enrollment-only');

    const confirmed = await t.auth.twoFactor.confirmEnrollment({
      session,
      code: t.codeFor(started.value.secret),
      meta: meta(),
    });

    expect(confirmed.ok).toBe(true);

    const calls = t.policy.calls;
    const validated = await t.sessionOf(token);

    expect(validated).not.toBeNull();
    expect(validated && 'twoFactor' in validated).toBe(false);
    // An enrolled user stops at the factor read: the policy is not asked.
    expect(t.policy.calls).toBe(calls);
  });

  it('asks a stale enrollment-only session to re-authenticate before it enrolls', async () => {
    const t = enforcedApp();
    const { token, session } = await t.signedIn();

    t.clock.advance(11 * MINUTE);
    t.policy.current = { required: true };

    const live = (await t.sessionOf(token)) as StoredSession<Record<string, never>>;

    expect(await t.auth.twoFactor.enroll({ session: live, meta: meta() })).toMatchObject({
      ok: false,
      code: 'fresh_auth_required',
    });

    const reauth = await t.auth.reauthenticate({ session, password: PASSWORD, meta: meta() });

    if (!reauth.ok) throw new Error(reauth.reason);

    expect(await t.sessionOf(reauth.value.token)).toMatchObject({
      twoFactor: { state: 'enrollment-only' },
    });

    const started = await t.auth.twoFactor.enroll({
      session: reauth.value.session,
      meta: meta(),
    });

    expect(started.ok).toBe(true);
  });

  it('can sign out', async () => {
    const t = enforcedApp({ required: true });
    const { token } = await t.signedIn();

    await t.auth.logout({ token, meta: meta() });

    expect(await t.sessionOf(token)).toBeNull();
  });
});

describe('an enrolled user', () => {
  it('is challenged at login and never flagged', async () => {
    const t = enforcedApp({ required: true });
    const { secret } = await t.enrolled();

    const challenge = await t.challenged();

    expect(challenge.methods).toContain('totp');

    const issued = await t.passed(secret);

    expect(await t.sessionOf(issued.token)).not.toHaveProperty('twoFactor');
  });

  it('cannot turn the factor off while it is required', async () => {
    const t = enforcedApp({ required: true });
    const { session } = await t.enrolled();

    expect(await t.auth.twoFactor.disable({ session, meta: meta() })).toMatchObject({
      ok: false,
      code: 'forbidden',
      reason: 'factor_required',
    });
  });
});

describe('a policy change', () => {
  it('applies on the next request, both ways, without a new sign-in', async () => {
    const t = enforcedApp({ required: false });
    const { token } = await t.signedIn();

    expect(await t.sessionOf(token)).not.toHaveProperty('twoFactor');

    t.policy.current = { required: true, graceEndsAt: t.clock.now() + MINUTE };
    expect((await t.sessionOf(token))?.twoFactor?.state).toBe('grace');

    t.policy.current = { required: true, graceEndsAt: null };
    expect((await t.sessionOf(token))?.twoFactor?.state).toBe('enrollment-only');

    t.policy.current = { required: false };
    expect(await t.sessionOf(token)).not.toHaveProperty('twoFactor');
  });
});

describe('a policy that fails', () => {
  it('reads as enrollment-only and logs the error name only', async () => {
    const t = enforcedApp({ required: false });
    const { token } = await t.signedIn();

    t.policy.current = thrower;

    expect((await t.sessionOf(token))?.twoFactor).toEqual({ state: 'enrollment-only' });

    expect(t.logged).toEqual([
      {
        message: 'twoFactor: the enforcement policy threw; read as enrollment-only',
        context: { error: 'TypeError' },
      },
    ]);

    // Nothing the app wrote into the message reaches the log.
    expect(JSON.stringify(t.logged)).not.toContain(EMAIL);
  });

  it('logs a thrown non-error by its type', async () => {
    const t = enforcedApp({ required: false });
    const { token } = await t.signedIn();

    const down: unknown = 'down';

    t.policy.current = () => {
      throw down;
    };

    expect((await t.sessionOf(token))?.twoFactor?.state).toBe('enrollment-only');
    expect(t.logged.map((entry) => entry.context)).toEqual([{ error: 'string' }]);
  });

  it('gives the session of a user who is gone the narrowest standing', async () => {
    const t = enforcedApp({ required: false });
    const { token } = await t.signedIn();

    vi.spyOn(t.stores.users, 'findById').mockResolvedValue(null);

    expect((await t.sessionOf(token))?.twoFactor?.state).toBe('enrollment-only');
  });

  it('reads a missing answer or an unreadable grace end as no grace', async () => {
    const t = enforcedApp({ required: false });
    const { token } = await t.signedIn();

    t.policy.current = null as never;
    expect((await t.sessionOf(token))?.twoFactor?.state).toBe('enrollment-only');

    t.policy.current = { required: true, graceEndsAt: new Date('not a date') };
    expect((await t.sessionOf(token))?.twoFactor?.state).toBe('enrollment-only');
  });

  it('does not let an app hook loosen the plugin standing', async () => {
    const t = enforcedApp(
      { required: true },
      { hooks: { sessionStanding: () => ({ twoFactor: { state: 'grace', graceEndsAt: 1 } }) } },
    );

    const { token } = await t.signedIn();

    expect((await t.sessionOf(token))?.twoFactor?.state).toBe('enrollment-only');
  });
});

describe('status', () => {
  it('asks a custom enforcement function once per call', async () => {
    const t = enforcedApp({ required: true, graceEndsAt: Date.now() + 60 * MINUTE });
    const { session } = await t.signedIn();

    t.policy.calls = 0;

    const status = await t.auth.twoFactor.status(session);

    expect(t.policy.calls).toBe(1);
    expect(status).toMatchObject({ ok: true, value: { required: true } });
  });
});

describe('sweepUnenrolled', () => {
  /** Signs up and in a user per email, enrolling those in `enrolled`. */
  async function population(t: ReturnType<typeof enforcedApp>) {
    const past = await t.signedIn('past@example.com');
    const grace = await t.signedIn('grace@example.com');
    const enrolled = await t.enrolled('enrolled@example.com');
    const quiet = await t.signedIn('quiet@example.com');
    const broken = await t.signedIn('broken@example.com');

    await t.auth.logout({ token: quiet.token, meta: meta() });

    return { past, grace, enrolled, quiet, broken };
  }

  it('revokes the sessions of required users past grace without a factor, and only those', async () => {
    const revocations: unknown[] = [];

    const t = enforcedApp(
      { required: false },
      { hooks: { onSessionsRevoked: (context: unknown) => void revocations.push(context) } },
    );

    const users = await population(t);
    const now = t.clock.now();

    const byEmail: Record<string, Policy> = {
      'past@example.com': { required: true, graceEndsAt: now - 1 },
      'grace@example.com': { required: true, graceEndsAt: now + MINUTE },
      'enrolled@example.com': { required: true },
      'quiet@example.com': { required: true },
      'broken@example.com': thrower,
    };

    t.policy.current = (user) => {
      const answer = byEmail[user.email] ?? { required: false };

      return typeof answer === 'function' ? answer(user) : answer;
    };

    revocations.length = 0;

    async function* ids() {
      for (const u of Object.values(users)) yield u.session.userId;

      yield 'no-such-user';
    }

    const result = await t.auth.twoFactor.sweepUnenrolled({ userIds: ids() });

    expect(result).toEqual({ checked: 6, revoked: [users.past.session.userId], failed: 1 });

    expect(revocations).toEqual([
      {
        userId: users.past.session.userId,
        sessionIds: [users.past.session.id],
        sessionHandles: [t.auth.sessions.handle(users.past.session.id)],
        reason: 'two-factor-required',
      },
    ]);

    expect(await t.sessionOf(users.past.token)).toBeNull();
    expect(await t.sessionOf(users.grace.token)).not.toBeNull();
    expect(await t.sessionOf(users.enrolled.token)).not.toBeNull();
    expect(await t.sessionOf(users.broken.token)).not.toBeNull();

    expect(
      t.audit.events.some(
        (e) => e.type === 'sessions.revoked' && e.reason === 'two-factor-required',
      ),
    ).toBe(true);
  });

  it('keeps the sessions of a user who enrolled after the first read', async () => {
    const t = enforcedApp({ required: true });
    const signed = await t.signedIn();
    const real = t.store.findFactor.bind(t.store);
    let reads = 0;

    // The first read sees no factor; by the next one the user has enrolled.
    t.store.findFactor = async (userId) =>
      ++reads === 1 ? real(userId) : ({ confirmed: true } as never);

    const result = await t.auth.twoFactor.sweepUnenrolled({ userIds: [signed.session.userId] });

    expect(result).toEqual({ checked: 1, revoked: [], failed: 0 });
    expect(reads).toBe(2);
    expect(await t.sessionOf(signed.token)).not.toBeNull();
  });

  it('keeps the sessions of a user whose rule changed after the first read', async () => {
    const t = enforcedApp({ required: true });
    const signed = await t.signedIn();
    let asked = 0;

    t.policy.current = () => (++asked === 1 ? { required: true } : { required: false });

    const result = await t.auth.twoFactor.sweepUnenrolled({ userIds: [signed.session.userId] });

    expect(result).toEqual({ checked: 1, revoked: [], failed: 0 });
    expect(asked).toBe(2);
    expect(await t.sessionOf(signed.token)).not.toBeNull();
  });

  it('takes a plain array, and does nothing when enforcement is off', async () => {
    const off = twoFactorApp();
    const { session } = await off.signedIn();

    expect(await off.auth.twoFactor.sweepUnenrolled({ userIds: [session.userId] })).toEqual({
      checked: 0,
      revoked: [],
      failed: 0,
    });

    const t = enforcedApp({ required: true });
    const signed = await t.signedIn();

    expect(await t.auth.twoFactor.sweepUnenrolled({ userIds: [signed.session.userId] })).toEqual({
      checked: 1,
      revoked: [signed.session.userId],
      failed: 0,
    });
  });
});
