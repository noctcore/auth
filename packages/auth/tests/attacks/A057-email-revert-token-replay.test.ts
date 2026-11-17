// A057: replaying an email revert link.
//
// The revert link restores the old address and locks the account down. Replayed
// later (from a forwarded mail, or by whoever reads the old mailbox), it could
// undo a change the owner made on purpose afterwards, or strip the password again.
//
// Stopped by: flows/email-change.ts (the revert link is purpose-bound,
//   `email-revert`, and consumed by one atomic delete), tokens/one-time-tokens.ts
//   (32 random bytes, only the SHA-256 stored; expiry checked after the consume).
// Learn: Email change (/auth/learn/email-change/)
import { describe, expect, it } from 'vitest';

import { meta, setup } from './support';
import { changed } from '../flows/email-change-support';

describe('A057: replaying an email revert link', () => {
  it('works once, even under 20 concurrent clicks', async () => {
    const t = setup();
    const { session } = await t.signedInUser();
    const { revert } = await changed(t, session, 'grace@example.com');

    const clicks = await Promise.all(
      Array.from({ length: 20 }, () => t.auth.revertEmailChange({ token: revert, meta: meta() })),
    );

    expect(clicks.filter((c) => c.ok)).toHaveLength(1);
    expect(t.audit.events.filter((e) => e.type === 'email.change_reverted')).toHaveLength(1);
  });

  it('a spent link cannot undo a later change', async () => {
    const t = setup();
    const { session } = await t.signedInUser();
    const { revert } = await changed(t, session, 'grace@example.com');

    expect((await t.auth.revertEmailChange({ token: revert, meta: meta() })).ok).toBe(true);

    expect(await t.auth.revertEmailChange({ token: revert, meta: meta() })).toMatchObject({
      ok: false,
      code: 'invalid_token',
      reason: 'email_revert_unknown',
    });
  });

  it('is bound to its purpose: a confirmation link or a reset link cannot revert, nor the reverse', async () => {
    const t = setup({ emailChange: { kind: 'link' } });
    const { session } = await t.signedInUser();

    await t.auth.requestEmailChange({ session, newEmail: 'grace@example.com', meta: meta() });

    const confirm = (t.mailer.last('email-change-confirm')?.url ?? '').split('#')[1] ?? '';

    expect(await t.auth.revertEmailChange({ token: confirm, meta: meta() })).toMatchObject({
      ok: false,
      reason: 'email_revert_unknown',
    });

    const done = await t.auth.confirmEmailChangeLink({ token: confirm, session, meta: meta() });

    if (!done.ok) throw new Error(done.reason);

    const revert = (t.mailer.last('email-changed')?.revertUrl ?? '').split('#')[1] ?? '';

    expect(
      await t.auth.resetPassword({
        token: revert,
        password: 'a brand new passphrase',
        meta: meta(),
      }),
    ).toMatchObject({ ok: false, code: 'invalid_token' });

    expect(
      await t.auth.confirmEmailChangeLink({ token: revert, session: null, meta: meta() }),
    ).toMatchObject({ ok: false, code: 'invalid_token' });

    expect((await t.auth.revertEmailChange({ token: revert, meta: meta() })).ok).toBe(true);
  });
});
