// A069: learning whether an address has an account through invitations.
//
// An inviter (any user the app lets invite) types addresses and watches the
// answer, the mail or the timing: "already a member", a different mail
// template, a slower path. A stranger tries tokens and reads the refusals.
//
// Stopped by: plugins/invitations/manage.ts (`create` never reads the invited
//   address from the user store: its answer, its store and throttle calls and its
//   mail are the same for any address); plugins/invitations/accept.ts (junk, unknown
//   and expired tokens all answer `invalid_token` before any user is read).
// Not stopped: `register` with a valid token answers `email_in_use` for an address
//   with an account; only the holder of a live token for that address sees it.
// Learn: Learn, Invitations (/auth/learn/invitations/)
import { describe, expect, it, vi } from 'vitest';

import { invitationApp, meta } from '../invitations/setup';

describe('A069: learning whether an address has an account through invitations', () => {
  it('answers, mails and calls the stores the same for a known and an unknown address', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });

    await t.user({ email: 'known@example.com' });

    const findByEmail = vi.spyOn(t.stores.users, 'findCredentialByEmail');
    const findById = vi.spyOn(t.stores.users, 'findById');

    async function probe(email: string) {
      findByEmail.mockClear();
      findById.mockClear();

      const result = await t.auth.invitations.create({
        session: inviter.session,
        scope: 'org_1',
        email,
        meta: meta(),
      });

      const mail = t.mailer.last('invitation') as Record<string, unknown>;

      return {
        ok: result.ok,
        keys: Object.keys(result.ok ? (result.value.invitation ?? {}) : {}).sort(),
        mail: Object.keys(mail).sort(),
        emailLookups: findByEmail.mock.calls.length,
        idLookups: findById.mock.calls.map(([id]) => id),
      };
    }

    expect(await probe('known@example.com')).toEqual(await probe('unknown@example.com'));
    expect(findByEmail).not.toHaveBeenCalled();
  });

  it('answers every token that is not a live invitation the same, before reading any user', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });
    const bob = await t.user({ email: 'bob@example.com' });
    const { token } = await t.invite(inviter, 'bob@example.com');
    const findById = vi.spyOn(t.stores.users, 'findById');

    const accept = async (value: string) => {
      const result = await t.auth.invitations.accept({
        session: bob.session,
        token: value,
        meta: meta(),
      });

      return result.ok ? 'ok' : result.code;
    };

    t.clock.advance(7 * 24 * 60 * 60_000);

    expect([await accept('junk'), await accept('c'.repeat(64)), await accept(token)]).toEqual([
      'invalid_token',
      'invalid_token',
      'invalid_token',
    ]);

    expect(findById).not.toHaveBeenCalled();
  });
});
