// A078: racing two email changes.
//
// Two changes in flight at once: two requests from one account (to slip an
// old code past the replacement), two confirmations of one code, or two
// accounts confirming the same new address at the same moment so both end up
// holding it.
//
// Stopped by: tokens/one-time-tokens.ts (one pending change per user: a new
//   request replaces the old token; consuming is one atomic delete),
//   ports/stores.ts (`changeEmail` is a compare-and-set on the old address and
//   keeps the address unique: of two accounts racing for one address exactly
//   one gets it), testing/conformance/user-store.ts (checks both under concurrency).
// Learn: Email change (/auth/learn/email-change/)
import { describe, expect, it } from 'vitest';

import { meta, setup } from './support';
import { requestCode } from '../flows/email-change-support';

describe('A078: racing two email changes', () => {
  it('of two concurrent requests from one account, only one code stays live', async () => {
    const t = setup();
    const { session } = await t.signedInUser();

    await Promise.all([
      t.auth.requestEmailChange({ session, newEmail: 'one@example.com', meta: meta() }),
      t.auth.requestEmailChange({ session, newEmail: 'two@example.com', meta: meta() }),
    ]);

    const codes = t.mailer.sent.flatMap((m) => (m.type === 'email-change-confirm' ? [m] : []));

    expect(codes).toHaveLength(2);

    const results = [];

    for (const mail of codes)
      results.push(
        await t.auth.confirmEmailChangeCode({ session, code: mail.code ?? '', meta: meta() }),
      );

    expect(results.filter((r) => r.ok)).toHaveLength(1);
  });

  it('of two concurrent confirmations of one code, exactly one moves the account', async () => {
    const t = setup();
    const { session } = await t.signedInUser();
    const code = await requestCode(t, session, 'grace@example.com');

    const results = await Promise.all([
      t.auth.confirmEmailChangeCode({ session, code, meta: meta() }),
      t.auth.confirmEmailChangeCode({ session, code, meta: meta() }),
    ]);

    expect(results.filter((r) => r.ok)).toHaveLength(1);
    expect(t.mailer.sent.filter((m) => m.type === 'email-changed')).toHaveLength(1);
  });

  it('of two accounts confirming one address at once, exactly one gets it', async () => {
    const t = setup();
    const first = await t.signedInUser('ada@example.com');
    const second = await t.signedInUser('eve@example.com', '198.51.100.20');
    const codeA = await requestCode(t, first.session, 'shared@example.com');
    const codeB = await requestCode(t, second.session, 'shared@example.com');

    const results = await Promise.all([
      t.auth.confirmEmailChangeCode({ session: first.session, code: codeA, meta: meta() }),
      t.auth.confirmEmailChangeCode({ session: second.session, code: codeB, meta: meta() }),
    ]);

    expect(results.filter((r) => r.ok)).toHaveLength(1);

    expect(results.find((r) => !r.ok)).toMatchObject({
      code: 'email_in_use',
      reason: 'email_change_taken',
    });

    const holders = await Promise.all(
      [first, second].map(async (u) => (await t.stores.users.findById(u.session.userId))?.email),
    );

    expect(holders.filter((e) => e === 'shared@example.com')).toHaveLength(1);
  });
});
