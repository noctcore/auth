// A073: reusing an email change code or link.
//
// A code or link that already moved the account is replayed: after the owner
// changed back, or from a mail copy the attacker kept, to move the account
// again without a new proof from the mailbox.
//
// Stopped by: tokens/one-time-tokens.ts (a code or link is consumed by one
//   atomic delete; one live token per user and purpose), flows/email-change.ts
//   (the token carries the address it replaces, and the store write is a
//   compare-and-set on it).
// Learn: Email change (/auth/learn/email-change/)
import { describe, expect, it } from 'vitest';

import { meta, setup } from './support';
import { requestCode, tokenOf } from '../flows/email-change-support';

describe('A073: reusing an email change code or link', () => {
  it('a code works once', async () => {
    const t = setup();
    const { session } = await t.signedInUser();
    const code = await requestCode(t, session, 'grace@example.com');
    const first = await t.auth.confirmEmailChangeCode({ session, code, meta: meta() });

    if (!first.ok || !first.value.session) throw new Error('confirm failed');

    const again = await t.auth.confirmEmailChangeCode({
      session: first.value.session.session,
      code,
      meta: meta(),
    });

    expect(again).toMatchObject({
      ok: false,
      code: 'invalid_token',
      reason: 'email_change_unknown',
    });
  });

  it('a link works once, even under 20 concurrent clicks', async () => {
    const t = setup({ emailChange: { kind: 'link' } });
    const { session } = await t.signedInUser();

    await t.auth.requestEmailChange({ session, newEmail: 'grace@example.com', meta: meta() });

    const token = tokenOf(t.mailer.last('email-change-confirm')?.url);

    const clicks = await Promise.all(
      Array.from({ length: 20 }, () =>
        t.auth.confirmEmailChangeLink({ token, session, meta: meta() }),
      ),
    );

    expect(clicks.filter((c) => c.ok)).toHaveLength(1);
    expect(t.audit.events.filter((e) => e.type === 'email.changed')).toHaveLength(1);
  });

  it('a link stored as its hash cannot be replayed from a leaked token table', async () => {
    const t = setup({ emailChange: { kind: 'link' } });
    const { session } = await t.signedInUser();

    await t.auth.requestEmailChange({ session, newEmail: 'grace@example.com', meta: meta() });

    const token = tokenOf(t.mailer.last('email-change-confirm')?.url);
    const stored = await t.stores.tokens.findByUser('email-change', session.userId);

    expect(stored?.hash).not.toBe(token);
    expect(JSON.stringify(stored)).not.toContain(token);

    expect(
      await t.auth.confirmEmailChangeLink({ token: stored?.hash ?? '', session, meta: meta() }),
    ).toMatchObject({ ok: false, code: 'invalid_token' });
  });
});
