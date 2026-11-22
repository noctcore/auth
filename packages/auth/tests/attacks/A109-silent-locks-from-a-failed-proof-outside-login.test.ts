// A109: locking an account through a failed proof outside login's gate, with
// nobody told.
//
// An app feeds the failures of its own proofs (its own second factor, a PIN)
// into the lockout's account-wide budget. `throttle.recordFailure` only
// counts: the lock it reports was turned into nothing, so the owner got no
// lock notice, no audit row was written and a permanent lock left every
// session alive, unless each app rebuilt the password path's notice by hand.
//
// Stopped by: core/auth-core.ts (`recordFailedProof`: the failure counts in
//   the account-wide budget, and a new lock goes through the same announcement
//   as a password lock), flows/lock-notice.ts (the `lockout` mail, the
//   `account.locked` or `account.locked_permanently` audit row and, for a
//   permanent lock, the end of the sessions and the `onPermanentLock` hooks),
//   create-auth.ts (wires the one announcement into the core).
// Learn: Brute force and lockout (/auth/learn/brute-force-and-lockout/)
import { describe, expect, it, vi } from 'vitest';

import type { LockoutOptions } from '../../src';
import { EMAIL, meta, PASSWORD, settled, setup } from './support';

const MIN = 60_000;

/** The account-wide budget of two: the third failure in a window locks. */
const SMALL = { perAccount: { limit: 2, window: '15m' } } as const satisfies LockoutOptions;

/** Signs `EMAIL` in, then waits out the window its own login attempt counted in. */
async function owner(t: ReturnType<typeof setup>) {
  const signedIn = await t.signedInUser(EMAIL);

  t.clock.advance(15 * MIN);

  return signedIn;
}

/** Three failed proofs of the app's own: one new lock. */
async function failThrice(t: ReturnType<typeof setup>, userId: string) {
  const results = [];

  for (let i = 0; i < 3; i++)
    results.push(await t.auth.context.recordFailedProof({ userId, meta: meta() }));

  await settled();

  return results;
}

describe('A109: silent locks from a failed proof outside login', () => {
  it('sends exactly one lock notice and audit row per lock, however many failures follow under it', async () => {
    const t = setup({ throttle: { lockout: SMALL } });
    const { session } = await owner(t);

    const results = await failThrice(t, session.userId);

    expect(results.map((r) => r.newLock !== undefined)).toEqual([false, false, true]);

    // Three more cross the limit again under the same lock: counted, not announced.
    await failThrice(t, session.userId);

    expect(t.mailer.sent.filter((m) => m.type === 'lockout')).toEqual([
      expect.objectContaining({ to: EMAIL, userId: session.userId }),
    ]);

    expect(t.audit.types().filter((type) => type === 'account.locked')).toHaveLength(1);

    const login = await t.auth.login({ email: EMAIL, password: PASSWORD, meta: meta('192.0.2.9') });

    expect(login).toMatchObject({ ok: false, reason: 'locked' });
  });

  it('carries a permanent lock out like a password one: the notice, the audit row, the sessions end', async () => {
    const revoked = vi.fn();
    const permanentHook = vi.fn();

    const t = setup({
      throttle: { lockout: { ...SMALL, permanent: { afterLocks: 1 } } },
      hooks: { onSessionsRevoked: revoked, onPermanentLock: permanentHook },
    });

    const { session, token } = await owner(t);

    await failThrice(t, session.userId);
    t.clock.advance(5 * MIN);

    const second = await failThrice(t, session.userId);

    expect(second[2]?.newLock).toMatchObject({ permanent: true });

    await settled();

    expect(t.mailer.sent.filter((m) => m.type === 'lockout' && m.permanent)).toHaveLength(1);
    expect(t.audit.types().filter((type) => type === 'account.locked_permanently')).toHaveLength(1);
    expect(revoked).toHaveBeenCalledWith(expect.objectContaining({ reason: 'locked-permanently' }));
    expect(permanentHook).toHaveBeenCalledOnce();
    expect((await t.auth.validateRequest({ token, meta: meta() })).ok).toBe(false);
  });

  it('counts an address with no account the same and tells nobody', async () => {
    const t = setup({ throttle: { lockout: SMALL } });
    const ghost = 'ghost@example.com';

    for (let i = 0; i < 3; i++)
      await t.auth.context.recordFailedProof({ email: ghost, meta: meta() });

    await settled();

    expect((await t.auth.lockout.inspect({ email: ghost })).locked).toBe(true);
    expect(t.mailer.sent.filter((m) => m.type === 'lockout')).toEqual([]);
  });
});
