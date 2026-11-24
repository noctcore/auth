// A058: learning whether an address has an account through the email change answer.
//
// A signed-in attacker asks to change their own email to address after
// address and watches the answer, the expiry and the store round trips: any
// difference between a taken and a free address is an account oracle.
//
// Stopped by: flows/email-change.ts (a taken and a free address get the same
//   answer after the same store calls: both look the address up and issue a
//   token before they part; the requester gets a code only for a free address,
//   and the owner of a taken one gets an "in use" mail instead), ports/mail.ts
//   (`email-change-in-use`).
// Learn: Email change (/auth/learn/email-change/), Enumeration (/auth/learn/enumeration/)
import { describe, expect, it } from 'vitest';

import { meta, PASSWORD, recordStoreCalls, settled, setup } from './support';

describe('A058: learning whether an address has an account through the email change answer', () => {
  it('answers a taken and a free address the same, with the same store calls', async () => {
    const t = setup();
    const { session } = await t.signedInUser('eve@example.com');

    await t.auth.register({
      email: 'ada@example.com',
      password: PASSWORD,
      meta: meta('198.51.100.2'),
    });

    const { calls } = recordStoreCalls(t.stores);

    const trace = async (newEmail: string) => {
      calls.length = 0;
      const answer = await t.auth.requestEmailChange({ session, newEmail, meta: meta() });

      return { answer, calls: [...calls] };
    };

    const taken = await trace('ada@example.com');
    const free = await trace('ghost@example.com');

    expect(taken.answer).toEqual(free.answer);
    expect(taken.answer.ok).toBe(true);
    expect(taken.calls).toEqual(free.calls);

    const audit = t.audit.events.filter((e) => e.type === 'email.change_requested');

    expect(audit).toHaveLength(2);
    expect(audit[0]).toEqual(audit[1]);
  });

  it('the code goes only to a free address; a taken one gets an "in use" mail to its owner', async () => {
    const t = setup();
    const { session } = await t.signedInUser('eve@example.com');

    await t.auth.register({
      email: 'ada@example.com',
      password: PASSWORD,
      meta: meta('198.51.100.2'),
    });

    await settled();

    const before = t.mailer.sent.length;

    await t.auth.requestEmailChange({ session, newEmail: 'ADA@example.com', meta: meta() });

    const mails = t.mailer.sent.slice(before);

    expect(mails).toHaveLength(1);
    expect(mails[0]).toMatchObject({ type: 'email-change-in-use', to: 'ada@example.com' });
    expect(JSON.stringify(mails)).not.toMatch(/"code"|"url"/u);
    // Nor where the request came from: the requester is another account.
    expect(mails[0]).not.toHaveProperty('meta');
    // An invitation mail carries no user id, so narrow before reading it.
    const first = mails[0];

    expect(first && 'userId' in first ? first.userId : undefined).not.toBe(session.userId);

    // The token issued on the taken path is never shown to anyone, so no code confirms it.
    for (let i = 0; i < 3; i++) {
      expect(
        (
          await t.auth.confirmEmailChangeCode({
            session,
            code: String(i).padStart(8, '0'),
            meta: meta(),
          })
        ).ok,
      ).toBe(false);
    }

    expect((await t.stores.users.findById(session.userId))?.email).toBe('eve@example.com');
  });

  it('refusals before the lookup do not depend on the address either', async () => {
    const t = setup();
    const { session } = await t.signedInUser('eve@example.com');

    await t.auth.register({
      email: 'ada@example.com',
      password: PASSWORD,
      meta: meta('198.51.100.2'),
    });

    t.clock.advance(10 * 60_000 + 1);

    const taken = await t.auth.requestEmailChange({
      session,
      newEmail: 'ada@example.com',
      meta: meta(),
    });

    const free = await t.auth.requestEmailChange({
      session,
      newEmail: 'ghost@example.com',
      meta: meta(),
    });

    expect(taken).toEqual(free);
  });
});
