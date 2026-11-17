// A060: taking the account back after the owner reverted the change.
//
// The intruder plans for the revert: a second change to void the owner's
// revert link, a reset link or a trusted device kept from before, or simply
// changing straight back to their address once the owner is in again.
//
// Stopped by: flows/email-change.ts (a live revert link is never replaced, so
//   a later change gets none and the owner's still works; a revert voids
//   reset, verification and change tokens, revokes every session, and blocks
//   the lost address for the account for 30 days by default),
//   plugins/two-factor/hooks.ts (the revocation also deletes trusted devices).
// Learn: Email change (/auth/learn/email-change/)
import { describe, expect, it } from 'vitest';

import { meta, PASSWORD, setup } from './support';
import { sha256Hex } from '../../src/crypto/hash';
import { changed } from '../flows/email-change-support';
import { twoFactorApp } from '../two-factor/setup';

const OWNER = 'ada@example.com';

describe('A060: taking the account back after the owner reverted the change', () => {
  it("a second change by the intruder does not void the owner's revert link, and gets none of its own", async () => {
    const t = setup();
    const { session } = await t.signedInUser(OWNER);
    const first = await changed(t, session, 'mallory@example.com');
    const second = await changed(t, first.session, 'mallory2@example.com');

    expect(second.revert).toBe('');
    expect(t.mailer.last('email-changed')).toMatchObject({ to: 'mallory@example.com' });
    expect(t.mailer.last('email-changed')?.revertUrl).toBeUndefined();

    expect((await t.auth.revertEmailChange({ token: first.revert, meta: meta() })).ok).toBe(true);
    expect((await t.stores.users.findById(session.userId))?.email).toBe(OWNER);
    expect(await t.stores.sessions.listByUser(session.userId)).toEqual([]);
  });

  it('the owner gets a fresh revert link for a change made after the old one lapsed', async () => {
    const t = setup();
    const { session } = await t.signedInUser(OWNER);

    await changed(t, session, 'grace@example.com');
    t.clock.advance(7 * 24 * 60 * 60_000 + 1);

    const login = await t.auth.login({
      email: 'grace@example.com',
      password: PASSWORD,
      meta: meta(),
    });

    if (!login.ok || login.value.kind !== 'session') throw new Error('login failed');

    const second = await changed(t, login.value.session.session, 'grace2@example.com');

    expect(second.revert).not.toBe('');
  });

  it('after the revert the intruder cannot change straight back to the lost address', async () => {
    const t = setup();
    const { session } = await t.signedInUser(OWNER);
    const taken = await changed(t, session, 'mallory@example.com');

    await t.auth.revertEmailChange({ token: taken.revert, meta: meta() });

    // Suppose the intruder still knows a password the owner sets again.
    await t.stores.users.setPasswordHash(
      session.userId,
      await t.auth.context.hasher.hash(PASSWORD),
    );

    const login = await t.auth.login({
      email: OWNER,
      password: PASSWORD,
      meta: meta('198.51.100.40'),
    });

    if (!login.ok || login.value.kind !== 'session') throw new Error('login failed');

    expect(
      await t.auth.requestEmailChange({
        session: login.value.session.session,
        newEmail: 'Mallory@Example.com',
        meta: meta('198.51.100.40'),
      }),
    ).toMatchObject({ ok: false, code: 'forbidden', reason: 'email_change_blocked' });
  });

  it('a pending change started by the intruder dies with the revert', async () => {
    const t = setup();
    const { session } = await t.signedInUser(OWNER);
    const taken = await changed(t, session, 'mallory@example.com');

    t.clock.advance(60_000);

    await t.auth.requestEmailChange({
      session: taken.session,
      newEmail: 'mallory3@example.com',
      meta: meta(),
    });

    const pending = t.mailer.last('email-change-confirm')?.code ?? '';

    await t.auth.revertEmailChange({ token: taken.revert, meta: meta() });

    expect(
      await t.auth.confirmEmailChangeCode({ session: taken.session, code: pending, meta: meta() }),
    ).toMatchObject({ ok: false, code: 'invalid_token' });

    expect(await t.stores.tokens.findByUser('email-change', session.userId)).toBeNull();
  });

  it('a revert deletes the trusted devices of a two-factor account', async () => {
    const t = twoFactorApp();
    const { secret, userId } = await t.enrolled();

    const remembered = await t.auth.twoFactor.verifyChallenge({
      challenge: (await t.challenged()).challenge,
      proof: { kind: 'totp', code: t.codeFor(secret) },
      rememberDevice: true,
      meta: meta(),
    });

    if (!remembered.ok) throw new Error(remembered.reason);

    t.nextStep();

    const session = remembered.value.session.session;
    const taken = await changed(t, session, 'mallory@example.com');
    const device = remembered.value.trustedDevice?.token ?? '';

    expect(device).not.toBe('');
    expect((await t.auth.revertEmailChange({ token: taken.revert, meta: meta() })).ok).toBe(true);
    expect(await t.store.findTrustedDevice(userId, sha256Hex(device))).toBeNull();
  });
});
