// A071: mail bombing someone through repeated invitations.
//
// Invitations send mail to any address an inviter types. A script that creates
// invitations in a loop, from one scope or many, turns the app into a mailer
// that floods a victim and burns the sender's reputation.
//
// Stopped by: ports/invitations.ts and plugins/invitations/manage.ts (one live
//   invitation per scope and address: a repeat writes nothing and sends no mail);
//   per-address (default 3 a day, across scopes, keyed by a keyed hash of the
//   address), per-inviter and per-IP windows, each refusing with `rate_limited`.
// Learn: Learn, Invitations (/auth/learn/invitations/)
import { describe, expect, it } from 'vitest';

import { invitationApp, meta } from '../invitations/setup';

describe('A071: mail bombing someone through repeated invitations', () => {
  it('sends one mail for a repeated invitation to one scope', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });

    for (let i = 0; i < 5; i++) {
      await t.auth.invitations.create({
        session: inviter.session,
        scope: 'org_1',
        email: 'victim@example.com',
        meta: meta(),
      });
    }

    expect(t.mailer.sent.filter((m) => m.type === 'invitation')).toHaveLength(1);
  });

  it('caps the invitations one address receives across scopes and inviters', async () => {
    const t = invitationApp();
    const first = await t.user({ canInvite: true });
    const second = await t.user({ canInvite: true });
    const results = [];

    for (let i = 0; i < 6; i++) {
      results.push(
        await t.auth.invitations.create({
          session: (i % 2 === 0 ? first : second).session,
          scope: `org_${i}`,
          email: 'victim@example.com',
          meta: meta(`198.51.100.${i}`),
        }),
      );
    }

    expect(results.map((r) => (r.ok ? 'sent' : r.reason))).toEqual([
      'sent',
      'sent',
      'sent',
      'rate_limited:invitation-address',
      'rate_limited:invitation-address',
      'rate_limited:invitation-address',
    ]);

    expect(t.mailer.sent.filter((m) => m.type === 'invitation')).toHaveLength(3);
  });

  it('caps the invitations one inviter sends', async () => {
    const t = invitationApp({ perInviter: { limit: 2, window: '1h' } });
    const inviter = await t.user({ canInvite: true });
    const reasons = [];

    for (let i = 0; i < 3; i++) {
      const result = await t.auth.invitations.create({
        session: inviter.session,
        scope: 'org_1',
        email: `victim${i}@example.com`,
        meta: meta(`198.51.100.${i}`),
      });

      reasons.push(result.ok ? 'sent' : result.reason);
    }

    expect(reasons).toEqual(['sent', 'sent', 'rate_limited:invitation-inviter']);
  });
});
