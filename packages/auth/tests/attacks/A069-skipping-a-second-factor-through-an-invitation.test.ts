// A069: getting a session past a second factor through an invitation.
//
// An invitation flow that "logs the invitee in" after accepting mints a
// session on the strength of the token alone: anyone who reads the victim's
// mail gets in without the victim's authenticator, and an app that requires a
// second factor gets an account with a session and none.
//
// Stopped by: plugins/invitations/accept.ts (`accept` needs a session the account
//   already holds and issues none; `register` only creates a new account and issues
//   its session through `issueSession` with `via: 'invitation'`, which the
//   two-factor plugin's `beforeSessionCreate` refuses whenever a factor is on or
//   required); plugins/two-factor/hooks.ts.
// Learn: Learn, Invitations (/auth/learn/invitations/)
import { describe, expect, it } from 'vitest';

import type { StoredSession } from '../../src';
import { invitations } from '../../src/plugins/invitations';
import { MemoryInvitationStore } from '../../src/testing';
import { meta, PASSWORD, twoFactorApp } from '../two-factor/setup';

type Session = StoredSession<Record<string, never>>;

function app(requiredFor: string | null) {
  const store = new MemoryInvitationStore();

  const plugin = invitations({
    store,
    authorize: () => true,
    onAccept: () => undefined,
    url: (token) => `https://app.example/invite#${token}`,
  });

  const t = twoFactorApp(
    { required: ({ user }) => user.email === requiredFor },
    { plugins: [plugin] },
  );

  const auth = t.auth as typeof t.auth & {
    invitations: ReturnType<NonNullable<typeof plugin.flows>>;
  };

  async function invite(session: Session, email: string) {
    await auth.invitations.create({ session, scope: 'org_1', email, meta: meta() });

    const mail = t.mailer.last('invitation') as { url: string };

    return mail.url.split('#')[1] ?? '';
  }

  return { ...t, auth, invite };
}

describe('A069: getting a session past a second factor through an invitation', () => {
  it('issues no session to an account with a factor that accepts', async () => {
    const t = app(null);
    const inviter = await t.signedIn('inviter@example.com');
    const victim = await t.enrolled('victim@example.com');

    await t.stores.users.markEmailVerified(victim.userId, 'victim@example.com' as never);

    const token = await t.invite(inviter.session, 'victim@example.com');

    const minted = () =>
      t.audit.events.filter((e) => e.type === 'session.created' && e.userId === victim.userId)
        .length;

    const before = minted();

    const accepted = await t.auth.invitations.accept({
      session: victim.session,
      token,
      meta: meta(),
    });

    expect(accepted.ok).toBe(true);
    expect(accepted).not.toHaveProperty('value.session');
    expect(minted()).toBe(before);
  });

  it('refuses to register through an invitation into an address that has a factor', async () => {
    const t = app(null);
    const inviter = await t.signedIn('inviter@example.com');

    await t.enrolled('victim@example.com');

    const token = await t.invite(inviter.session, 'victim@example.com');

    expect(
      await t.auth.invitations.register({ token, password: PASSWORD, meta: meta() }),
    ).toMatchObject({ ok: false, code: 'email_in_use' });
  });

  it('issues no session to a new account when the app requires a factor', async () => {
    const t = app('new@example.com');
    const inviter = await t.signedIn('inviter@example.com');
    const token = await t.invite(inviter.session, 'new@example.com');

    expect(
      await t.auth.invitations.register({ token, password: PASSWORD, meta: meta() }),
    ).toMatchObject({ ok: false, code: 'second_factor_required' });

    const user = await t.stores.users.findCredentialByEmail('new@example.com' as never);

    expect(
      t.audit.events.filter((e) => e.type === 'session.created' && e.userId === user?.id),
    ).toEqual([]);
  });
});
