// A083: using a verification link opened outside a session (linkWithoutSession).
//
// With `emailVerification.linkWithoutSession` an app accepts a verification
// link with no session. An attacker who gets hold of the link (a forwarded mail,
// a shared device) tries to turn it into a sign-in, a squatter who registered
// the address first tries to keep their session through the owner's click, and
// a link for one account is opened inside a session of another.
//
// Stopped by: flows/email-verification.ts (no session is issued without a live
//   session of the same account, the revocation bumps the epoch on every verify,
//   another account's session is refused and leaves the link unspent, the token
//   stays single-use and bound to the address it was sent to).
// Learn: Email verification and account pre-hijacking (/auth/learn/email-verification/)
import { describe, expect, it } from 'vitest';

import { meta, setup } from './support';

const linkTo = (app: ReturnType<typeof setup>, email: string) => {
  const mail = app.mailer.sent.filter((m) => m.type === 'verify-email' && m.to === email).at(-1);

  return (mail?.type === 'verify-email' ? (mail.url ?? '') : '').split('#')[1] ?? '';
};

const sessionless = () => setup({ emailVerification: { kind: 'link', linkWithoutSession: true } });

describe('A083: using a verification link opened outside a session', () => {
  it('verifies the address but hands out no session and mints none', async () => {
    const app = sessionless();
    const { session } = await app.signedInUser('victim@example.com');
    const created = () => app.audit.types().filter((t) => t === 'session.created').length;
    const before = created();

    const result = await app.auth.verifyEmailLink({
      token: linkTo(app, 'victim@example.com'),
      session: null,
      meta: meta('198.51.100.66'),
    });

    expect(result).toEqual({ ok: true, value: { session: null } });
    expect(await app.auth.context.sessions.listActive(session.userId)).toEqual([]);
    expect(created()).toBe(before);
  });

  it("ends a squatter's session when the mailbox owner clicks from another device", async () => {
    const app = sessionless();
    const squatter = await app.signedInUser('victim@example.com', '198.51.100.13');

    await app.auth.verifyEmailLink({
      token: linkTo(app, 'victim@example.com'),
      session: null,
      meta: meta(),
    });

    expect(await app.sessionOf(squatter.token)).toBeNull();
  });

  it("refuses the link inside another account's session and leaves it for its owner", async () => {
    const app = sessionless();
    const victim = await app.signedInUser('victim@example.com');
    const token = linkTo(app, 'victim@example.com');
    const eve = await app.signedInUser('eve@example.com', '198.51.100.9');

    const stolen = await app.auth.verifyEmailLink({ token, session: eve.session, meta: meta() });

    expect(!stolen.ok && stolen.reason).toBe('verification_session_required');
    expect((await app.stores.users.findById(victim.session.userId))?.emailVerified).toBe(false);

    const owner = await app.auth.verifyEmailLink({ token, session: null, meta: meta() });

    expect(owner.ok).toBe(true);
  });

  it('refuses a replayed link, and a link for an address the account gave up', async () => {
    const app = sessionless();
    const { session } = await app.signedInUser('victim@example.com');
    const first = linkTo(app, 'victim@example.com');

    await app.auth.verifyEmailLink({ token: first, session: null, meta: meta() });
    const replay = await app.auth.verifyEmailLink({ token: first, session: null, meta: meta() });

    expect(!replay.ok && replay.code).toBe('invalid_token');

    const owner = await app.signedInUser('old@example.com', '198.51.100.20');
    const stale = linkTo(app, 'old@example.com');

    await app.stores.users.setEmail(owner.session.userId, 'new@example.com' as never);

    const moved = await app.auth.verifyEmailLink({ token: stale, session: null, meta: meta() });

    expect(!moved.ok && moved.reason).toBe('verification_address_changed');
    expect((await app.stores.users.findById(owner.session.userId))?.emailVerified).toBe(false);
    expect((await app.stores.users.findById(session.userId))?.emailVerified).toBe(true);
  });
});
