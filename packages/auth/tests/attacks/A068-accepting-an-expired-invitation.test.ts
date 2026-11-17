// A068: accepting an invitation after it expired.
//
// A link found months later in an old mailbox, a backup or a leaked log still
// grants a seat if invitations never expire, long after the inviter forgot it.
//
// Stopped by: plugins/invitations/options.ts (lifetime 7 days by default, never more
//   than 30); plugins/invitations/accept.ts (an invitation at or past `expiresAt` is
//   refused as `invalid_token`, the same answer as an unknown one).
// Learn: Learn, Invitations (/auth/learn/invitations/)
import { describe, expect, it } from 'vitest';

import { invitations } from '../../src/plugins/invitations';
import { MemoryInvitationStore } from '../../src/testing';
import { invitationApp, meta, PASSWORD } from '../invitations/setup';

describe('A068: accepting an invitation after it expired', () => {
  it('refuses accept and register at the expiry, with the answer of an unknown token', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });
    const bob = await t.user({ email: 'bob@example.com' });
    const { token } = await t.invite(inviter, bob.email);
    const second = await t.invite(inviter, 'new@example.com');

    t.clock.advance(7 * 24 * 60 * 60_000);

    expect(await t.auth.invitations.accept({ session: bob.session, token, meta: meta() })).toEqual({
      ok: false,
      code: 'invalid_token',
      reason: 'expired_token',
    });

    expect(
      await t.auth.invitations.register({ token: second.token, password: PASSWORD, meta: meta() }),
    ).toEqual({ ok: false, code: 'invalid_token', reason: 'expired_token' });

    expect(t.onAccept).not.toHaveBeenCalled();
  });

  it('refuses a lifetime longer than 30 days', () => {
    expect(() =>
      invitations({
        store: new MemoryInvitationStore(),
        authorize: () => true,
        onAccept: () => undefined,
        url: (token) => `https://app.example/invite#${token}`,
        ttl: '31d',
      }),
    ).toThrow('invitations: ttl must be positive and at most 30 days');
  });
});
