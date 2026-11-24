// A reset whose password write the store refuses (an app's write guard, an
// account closed after the hooks ran) must leave no other reset link, code,
// ticket or pending email change of the account alive to try again.
import { describe, expect, it, vi } from 'vitest';
import { PASSWORD_PURPOSES } from '../../src/flows/settings';
import { codeFor, EMAIL, linkFor, meta, NEW_PASSWORD, queued } from '../attacks/support';

/** The account's live password tokens, by purpose. */
async function liveTokens(t: ReturnType<typeof queued>, userId: string) {
  const found = await Promise.all(
    PASSWORD_PURPOSES.map(async (purpose) => [
      purpose,
      await t.stores.tokens.findByUser(purpose, userId),
    ]),
  );

  return found.filter(([, token]) => token !== null).map(([purpose]) => purpose);
}

describe('a reset whose write the store refuses', () => {
  it('voids the pending code when a code ticket is refused', async () => {
    const t = queued({ passwordReset: { kind: 'code' } });
    const { session } = await t.signedInUser(EMAIL);

    const verified = await t.auth.verifyPasswordResetCode({
      email: EMAIL,
      code: await codeFor(t),
      meta: meta(),
    });

    if (!verified.ok) throw new Error('code refused');

    // A second reset asked for meanwhile: its code is waiting in the mailbox.
    const pending = await codeFor(t);

    vi.spyOn(t.stores.users, 'setPasswordHash').mockResolvedValueOnce(false);

    const refused = await t.auth.resetPassword({
      token: verified.value.ticket,
      password: NEW_PASSWORD,
      meta: meta(),
    });

    expect(refused).toMatchObject({
      ok: false,
      code: 'invalid_token',
      reason: 'reset_write_refused',
    });

    expect(await liveTokens(t, session.userId)).toEqual([]);

    const later = await t.auth.verifyPasswordResetCode({
      email: EMAIL,
      code: pending,
      meta: meta(),
    });

    expect(!later.ok && later.code).toBe('invalid_token');
  });

  it('voids a pending email change when a link is refused', async () => {
    const t = queued();
    const { session } = await t.signedInUser(EMAIL);

    await t.auth.requestEmailChange({ session, newEmail: 'new@example.com', meta: meta() });

    const link = await linkFor(t);

    expect(await liveTokens(t, session.userId)).toHaveLength(2);

    vi.spyOn(t.stores.users, 'setPasswordHash').mockResolvedValueOnce(false);

    const refused = await t.auth.resetPassword({
      token: link,
      password: NEW_PASSWORD,
      meta: meta(),
    });

    expect(refused).toMatchObject({ ok: false, reason: 'reset_write_refused' });
    expect(await liveTokens(t, session.userId)).toEqual([]);
  });
});
