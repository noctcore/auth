// A060: taking the account back after the owner reverted the change.
//
// The intruder plans for the revert: a second change to void the owner's
// revert link (or to strand the address it would restore), a reset link, a
// trusted device or a second factor kept from before, or simply changing
// straight back to their address once the owner is in again.
//
// Stopped by: flows/email-change.ts (no new change starts while a revert link
//   lives; a revert voids reset, verification and change tokens, revokes
//   every session, and blocks the lost address for the account for 30 days by
//   default), plugins/two-factor/hooks.ts (the revocation also deletes trusted
//   devices). A second factor survives a revert, the intruder's too: the
//   owner who cannot pass it goes to support (A063 for why it must stay).
// Learn: Email change (/auth/learn/email-change/)
import { describe, expect, it } from 'vitest';

import {
  meta,
  PASSWORD,
  queued,
  queuedTwoFactor,
  requestAndDrain,
  setup,
  tokenOf,
} from './support';
import { sha256Hex } from '../../src/crypto/hash';
import { changed } from '../flows/email-change-support';
import { twoFactorApp } from '../two-factor/setup';

const OWNER = 'ada@example.com';

describe('A060: taking the account back after the owner reverted the change', () => {
  it('the intruder cannot start a second change while the revert link lives, so it stays the one to use', async () => {
    const t = setup();
    const { session } = await t.signedInUser(OWNER);
    const first = await changed(t, session, 'mallory@example.com');

    expect(
      await t.auth.requestEmailChange({
        session: first.session,
        newEmail: 'mallory2@example.com',
        meta: meta(),
      }),
    ).toEqual({ ok: false, code: 'forbidden', reason: 'email_change_pending_revert' });

    expect(t.mailer.sent.filter((m) => m.type === 'email-change-confirm')).toHaveLength(1);
    expect(await t.stores.tokens.findByUser('email-change', session.userId)).toBeNull();

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

  it('a reset link the intruder requested before the revert dies with it', async () => {
    const t = queued();
    const { session } = await t.signedInUser(OWNER);
    const taken = await changed(t, session, 'mallory@example.com');

    await requestAndDrain(t, 'mallory@example.com');

    const reset = tokenOf(t.mailer.last('password-reset')?.url);

    expect(reset).not.toBe('');
    expect((await t.auth.revertEmailChange({ token: taken.revert, meta: meta() })).ok).toBe(true);

    expect(
      await t.auth.resetPassword({
        token: reset,
        password: 'a brand new passphrase',
        meta: meta(),
      }),
    ).toMatchObject({ ok: false, code: 'invalid_token' });
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

  it('a factor the intruder enrolled survives the revert, so the owner needs support to remove it', async () => {
    const t = queuedTwoFactor();
    const { session } = await t.signedIn();
    const taken = await changed(t, session, 'mallory@example.com');
    const started = await t.auth.twoFactor.enroll({ session: taken.session, meta: meta() });

    if (!started.ok) throw new Error(started.reason);

    await t.auth.twoFactor.confirmEnrollment({
      session: taken.session,
      code: t.codeFor(started.value.secret),
      meta: meta(),
    });

    expect((await t.auth.revertEmailChange({ token: taken.revert, meta: meta() })).ok).toBe(true);
    expect(await t.store.findFactor(session.userId)).toMatchObject({ confirmed: true });
    expect(t.audit.events.some((e) => e.type === 'two_factor.disabled')).toBe(false);

    const reset = await t.resetLinkFor(OWNER);

    expect(reset).not.toBe('');

    expect(
      await t.auth.resetPassword({ token: reset, password: 'the owner again!', meta: meta() }),
    ).toMatchObject({ ok: false, code: 'second_factor_required' });
  });
});
