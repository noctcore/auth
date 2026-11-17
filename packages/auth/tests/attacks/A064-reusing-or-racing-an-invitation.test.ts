// A064: reusing an invitation, or racing two accepts of one.
//
// The invitee clicks twice, opens the link in two browsers, or an attacker who
// saw the link replays it after the invitee accepted. An invitation checked and
// deleted in two steps lets both requests through, and each grants whatever
// the invitation carries (a role, a seat) once more.
//
// Stopped by: plugins/invitations/accept.ts (the invitation is spent through the
//   store's `consume`, which removes and returns it in one atomic step; only the
//   caller that got it runs `onAccept`); ports/invitations.ts (the contract), checked
//   under concurrency by the conformance suite for every store.
// Learn: Learn, Invitations (/auth/learn/invitations/)
import { describe, expect, it } from 'vitest';

import { invitationApp, meta, PASSWORD, SCOPE } from '../invitations/setup';

describe('A064: reusing an invitation, or racing two accepts of one', () => {
  it('accepts once, then refuses the same link', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });
    const bob = await t.user({ email: 'bob@example.com' });
    const { token } = await t.invite(inviter, bob.email);
    const input = { session: bob.session, token, meta: meta() };

    expect((await t.auth.invitations.accept(input)).ok).toBe(true);

    expect(await t.auth.invitations.accept(input)).toEqual({
      ok: false,
      code: 'invalid_token',
      reason: 'unknown_token',
    });

    expect(t.onAccept).toHaveBeenCalledTimes(1);
  });

  it('lets one of many concurrent accepts through, from any number of sessions', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });
    const bob = await t.user({ email: 'bob@example.com' });
    const { token } = await t.invite(inviter, bob.email);
    const second = await t.auth.login({ email: bob.email, password: PASSWORD, meta: meta() });

    if (!second.ok || second.value.kind !== 'session') throw new Error('login failed');

    const sessions = [bob.session, second.value.session.session];

    const results = await Promise.all(
      Array.from({ length: 10 }, (_, i) =>
        t.auth.invitations.accept({ session: sessions[i % 2] ?? bob.session, token, meta: meta() }),
      ),
    );

    expect(results.filter((r) => r.ok)).toHaveLength(1);
    expect(t.onAccept).toHaveBeenCalledTimes(1);
    expect(await t.store.listByScope(SCOPE, t.clock.now())).toEqual([]);
  });

  it('creates one account from many concurrent registrations with one link', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });
    const { token } = await t.invite(inviter, 'new@example.com');

    const results = await Promise.all(
      Array.from({ length: 5 }, () =>
        t.auth.invitations.register({ token, password: PASSWORD, meta: meta() }),
      ),
    );

    expect(results.filter((r) => r.ok)).toHaveLength(1);
    expect(t.onAccept).toHaveBeenCalledTimes(1);
  });
});
