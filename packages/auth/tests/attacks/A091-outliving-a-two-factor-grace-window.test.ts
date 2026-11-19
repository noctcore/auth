// A091: outliving a two-factor grace window without ever setting a factor up.
//
// An app that requires a second factor gives existing users a grace window.
// If the requirement is only checked at sign-in, a session from inside the
// window keeps working after it closes, and so does every session of a user
// who simply never signs in again. A policy lookup that fails, or another
// hook that says "grace", must not turn into "no requirement" either.
//
// Stopped by: plugins/two-factor/enforcement.ts (the standing is computed on
//   every validated request, never stored, so a closed window or a policy
//   change applies on the next request; a policy that throws or answers
//   nothing reads as required with no grace; `sweepUnenrolled` revokes the
//   sessions of users past their window) and flows/session-validation.ts
//   (an `enrollment-only` standing from any hook wins over a `grace`).
// Learn: Second factors (/auth/learn/second-factors/)
import { describe, expect, it } from 'vitest';

import type { AuthUser } from '../../src';
import type { TwoFactorPolicy } from '../../src/plugins/two-factor';
import { meta, twoFactorApp } from '../two-factor/setup';

const MINUTE = 60_000;

function app(hooks = {}) {
  const policy: { current: TwoFactorPolicy | ((user: AuthUser) => TwoFactorPolicy) } = {
    current: { required: false },
  };

  const t = twoFactorApp(
    {
      enforcement: ({ user }) =>
        typeof policy.current === 'function' ? policy.current(user) : policy.current,
    },
    { hooks, logger: { warn: () => undefined, error: () => undefined } },
  );

  return { ...t, policy };
}

describe('A091: outliving a two-factor grace window', () => {
  it('confines a session from inside the window once the window closes, without a new sign-in', async () => {
    const t = app();

    t.policy.current = { required: true, graceEndsAt: t.clock.now() + 5 * MINUTE };

    const { token } = await t.signedIn();

    expect((await t.sessionOf(token))?.twoFactor?.state).toBe('grace');

    t.clock.advance(5 * MINUTE);

    expect((await t.sessionOf(token))?.twoFactor).toEqual({ state: 'enrollment-only' });
  });

  it('confines a session the moment the policy starts requiring a factor', async () => {
    const t = app();
    const { token } = await t.signedIn();

    expect(await t.sessionOf(token)).not.toHaveProperty('twoFactor');

    t.policy.current = { required: true };

    expect((await t.sessionOf(token))?.twoFactor?.state).toBe('enrollment-only');
  });

  it('reads a policy that throws or answers nothing as required with no grace', async () => {
    const t = app();
    const { token } = await t.signedIn();

    t.policy.current = () => {
      throw new Error('tenant lookup timed out');
    };

    expect((await t.sessionOf(token))?.twoFactor?.state).toBe('enrollment-only');

    t.policy.current = undefined as never;

    expect((await t.sessionOf(token))?.twoFactor?.state).toBe('enrollment-only');
  });

  it('never lets another hook loosen enrollment-only back to grace', async () => {
    const t = app({
      sessionStanding: () => ({ twoFactor: { state: 'grace', graceEndsAt: Date.now() + MINUTE } }),
    });

    t.policy.current = { required: true };

    const { token } = await t.signedIn();

    expect((await t.sessionOf(token))?.twoFactor?.state).toBe('enrollment-only');
  });

  it('ends every session of a user past the window through the sweep', async () => {
    const t = app();
    const first = await t.signedIn();
    const second = await t.signedIn();

    t.policy.current = { required: true, graceEndsAt: t.clock.now() - 1 };

    const swept = await t.auth.twoFactor.sweepUnenrolled({ userIds: [first.session.userId] });

    expect(swept.revoked).toEqual([first.session.userId]);
    expect(await t.sessionOf(first.token)).toBeNull();
    expect(await t.sessionOf(second.token)).toBeNull();

    // The next sign-in is confined, not refused: the user can still enroll.
    const again = await t.signedIn();

    expect((await t.sessionOf(again.token))?.twoFactor?.state).toBe('enrollment-only');
    expect((await t.auth.twoFactor.enroll({ session: again.session, meta: meta() })).ok).toBe(true);
  });
});
