// A061: registering the old address so the revert has nowhere to go.
//
// The intruder changes the owner's account from A to B, then registers a new
// account on A (or moves another account they hold to A). The owner's revert
// link would restore A, but A now has an account: the revert fails, and the
// intruder keeps the account on B.
//
// Stopped by: flows/email-reservation.ts (A is held for the owner while the
//   revert link lives), flows/register.ts (a held address is answered as
//   taken: the same answer, one "account exists" mail to A for its owner, the
//   same number of store round trips before the answer, with a read of the
//   holder in the insert's place), flows/email-change.ts (other accounts'
//   requests and confirms treat a held address as taken; if A has an account
//   anyway, the revert still removes the password, revokes every session and
//   pending token, and keeps the link usable).
// Learn: Email change (/auth/learn/email-change/)
import { describe, expect, it } from 'vitest';

import { meta, onFakeClock, PASSWORD, recordStoreCalls, settled, setup } from './support';
import { plainHasher } from '../../src/testing';
import { changed } from '../flows/email-change-support';

const OWNER = 'ada@example.com';
const INTRUDER = 'mallory@example.com';

describe('A061: registering the old address so the revert has nowhere to go', () => {
  it('sign-up on the old address answers as taken, and the revert still restores it', async () => {
    const t = setup();
    const { session } = await t.signedInUser(OWNER);
    const taken = await changed(t, session, INTRUDER);
    const before = t.mailer.sent.length;

    expect(
      await t.auth.register({ email: 'Ada@Example.com', password: PASSWORD, meta: meta() }),
    ).toEqual({ ok: true, value: { session: null } });

    // The notice and its audit row are sent off the response path.
    await settled();

    expect(t.mailer.sent.slice(before)).toEqual([
      expect.objectContaining({ type: 'account-exists', to: OWNER, userId: session.userId }),
    ]);

    expect(t.audit.events.at(-1)).toMatchObject({
      type: 'register.existing',
      userId: session.userId,
    });

    expect(await t.stores.users.findCredentialByEmail(OWNER as never)).toBeNull();
    expect((await t.auth.revertEmailChange({ token: taken.revert, meta: meta() })).ok).toBe(true);
    expect((await t.stores.users.findById(session.userId))?.email).toBe(OWNER);
  });

  it('with revealExisting, sign-up on the old address says it is in use', async () => {
    const t = setup({ registration: { revealExisting: true } });
    const { session } = await t.signedInUser(OWNER);

    await changed(t, session, INTRUDER);

    expect(await t.auth.register({ email: OWNER, password: PASSWORD, meta: meta() })).toEqual({
      ok: false,
      code: 'email_in_use',
      reason: 'email_in_use',
    });
  });

  it('a held address costs sign-up the same store round trips, hash and mail as a taken one', async () => {
    let hashes = 0;
    const base = plainHasher();
    const hasher = { ...base, hash: async (p: string) => (hashes++, base.hash(p)) };
    const t = setup({ password: { hasher, breachCheck: false } });
    const { session } = await t.signedInUser(OWNER);

    await changed(t, session, INTRUDER);
    await t.auth.register({ email: 'eve@example.com', password: PASSWORD, meta: meta() });
    await settled();

    const { calls } = recordStoreCalls(t.stores);

    const trace = async (email: string) => {
      calls.length = 0;
      hashes = 0;

      const mailsBefore = t.mailer.sent.length;
      const answer = await t.auth.register({ email, password: PASSWORD, meta: meta() });

      await settled();

      return { answer, count: calls.length, hashes, mails: t.mailer.sent.length - mailsBefore };
    };

    const held = await trace(OWNER);
    const existing = await trace('eve@example.com');

    expect(held).toEqual(existing);
    expect(held.count).toBe(4);
  });

  it('a held address answers after a read of the holder in the insert place, without waiting on the owner lookup', async () => {
    const t = setup();
    const { session } = await t.signedInUser(OWNER);

    await changed(t, session, INTRUDER);

    t.stores.users.findCredentialByEmail = () => new Promise<never>(() => undefined);

    const { calls } = recordStoreCalls(t.stores);

    const answer = await onFakeClock(() =>
      t.auth.register({ email: OWNER, password: PASSWORD, meta: meta() }),
    );

    expect(answer).toEqual({ ok: true, value: { session: null } });
    expect(calls.slice(0, 3)).toEqual(['counters.increment', 'tokens.find', 'users.findById']);
  });

  it("another account's change request to the old address answers as taken and mails the owner", async () => {
    const t = setup();
    const { session } = await t.signedInUser(OWNER);

    await changed(t, session, INTRUDER);

    const accomplice = await t.signedInUser('eve@example.com', '198.51.100.9');
    const before = t.mailer.sent.length;

    const answer = await t.auth.requestEmailChange({
      session: accomplice.session,
      newEmail: OWNER,
      meta: meta('198.51.100.9'),
    });

    expect(answer.ok).toBe(true);

    const mails = t.mailer.sent.slice(before);

    expect(mails).toHaveLength(1);

    expect(mails[0]).toMatchObject({
      type: 'email-change-in-use',
      to: OWNER,
      userId: session.userId,
    });
  });

  it('if the old address has an account anyway, the revert locks the intruder out and the link waits', async () => {
    const t = setup();
    const { session } = await t.signedInUser(OWNER);
    const taken = await changed(t, session, INTRUDER);

    // Past the hold, as a store written to directly would be.
    const squatter = await t.stores.users.create({ email: OWNER as never, passwordHash: 'x' });

    expect(await t.auth.revertEmailChange({ token: taken.revert, meta: meta() })).toMatchObject({
      ok: false,
      code: 'email_in_use',
      reason: 'email_revert_address_taken',
    });

    expect((await t.auth.login({ email: INTRUDER, password: PASSWORD, meta: meta() })).ok).toBe(
      false,
    );

    expect(await t.stores.sessions.listByUser(session.userId)).toEqual([]);

    await t.stores.users.setEmail(squatter?.id ?? '', 'elsewhere@example.com' as never);

    expect((await t.auth.revertEmailChange({ token: taken.revert, meta: meta() })).ok).toBe(true);
    expect((await t.stores.users.findById(session.userId))?.email).toBe(OWNER);
  });
});
