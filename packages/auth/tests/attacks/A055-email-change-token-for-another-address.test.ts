// A055: confirming an email change with a proof meant for another address or account.
//
// The attacker holds a code for an address they control and tries to make it
// confirm a different change: one the owner started later, a change on another
// account, or a change whose old address no longer matches.
//
// Stopped by: tokens/one-time-tokens.ts (codes are an HMAC of purpose, user
//   and code; one pending change per user, so a new request replaces the old
//   code), flows/email-change.ts (the token stores the new address and the one
//   it replaces; confirmation refuses when the account's address moved, and the
//   store write is a compare-and-set on the old address).
// Learn: Email change (/auth/learn/email-change/)
import { describe, expect, it } from 'vitest';

import { meta, setup } from './support';
import { requestCode, tokenOf } from '../flows/email-change-support';

describe('A055: confirming an email change with a proof meant for another address or account', () => {
  it('a code for the first address dies when a second request replaces it', async () => {
    const t = setup();
    const { session } = await t.signedInUser();
    const first = await requestCode(t, session, 'mallory@example.com');
    const second = await requestCode(t, session, 'grace@example.com');

    expect(first).not.toBe(second);

    expect(
      await t.auth.confirmEmailChangeCode({ session, code: first, meta: meta() }),
    ).toMatchObject({
      ok: false,
      code: 'invalid_token',
    });

    expect((await t.auth.confirmEmailChangeCode({ session, code: second, meta: meta() })).ok).toBe(
      true,
    );

    expect((await t.stores.users.findById(session.userId))?.email).toBe('grace@example.com');
  });

  it("a code from one account cannot confirm another account's change", async () => {
    const t = setup();
    const victim = await t.signedInUser('ada@example.com');
    const attacker = await t.signedInUser('eve@example.com', '198.51.100.20');

    await requestCode(t, victim.session, 'grace@example.com');
    const mine = await requestCode(t, attacker.session, 'eve2@example.com');

    expect(
      await t.auth.confirmEmailChangeCode({ session: victim.session, code: mine, meta: meta() }),
    ).toMatchObject({ ok: false, code: 'invalid_token' });

    expect((await t.stores.users.findById(victim.session.userId))?.email).toBe('ada@example.com');
  });

  it('a link for another account is refused in this session and left for its owner', async () => {
    const t = setup({ emailChange: { kind: 'link' } });
    const owner = await t.signedInUser('ada@example.com');
    const other = await t.signedInUser('eve@example.com', '198.51.100.20');

    await t.auth.requestEmailChange({
      session: owner.session,
      newEmail: 'grace@example.com',
      meta: meta(),
    });

    const token = tokenOf(t.mailer.last('email-change-confirm')?.url);

    expect(
      await t.auth.confirmEmailChangeLink({ token, session: other.session, meta: meta() }),
    ).toMatchObject({ ok: false, reason: 'email_change_session_required' });

    expect(
      (await t.auth.confirmEmailChangeLink({ token, session: owner.session, meta: meta() })).ok,
    ).toBe(true);
  });

  it('a pending change dies when the account address moved by another route', async () => {
    const t = setup();
    const { session } = await t.signedInUser();
    const code = await requestCode(t, session, 'grace@example.com');

    await t.stores.users.setEmail(session.userId, 'support-moved@example.com' as never);

    expect(await t.auth.confirmEmailChangeCode({ session, code, meta: meta() })).toMatchObject({
      ok: false,
      code: 'invalid_token',
      reason: 'email_change_address_changed',
    });

    expect((await t.stores.users.findById(session.userId))?.email).toBe(
      'support-moved@example.com',
    );
  });
});
