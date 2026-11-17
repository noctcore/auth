// A040: using a login challenge as a session or a reset ticket.
//
// The challenge comes back to the browser after the password, before the
// second factor. If it were stored like a session token or a reset ticket, or
// checked by the same lookup, presenting it at those doors would skip the
// second factor.
//
// Stopped by: plugins/two-factor/challenge.ts (the challenge is a one-time token under its
//   own purpose, `two-factor-challenge`, never in the session store),
//   tokens/one-time-tokens.ts (every lookup is bound to its purpose).
// Learn: Second factors (/auth/learn/second-factors/)
import { describe, expect, it } from 'vitest';

import { meta, NEW_PASSWORD, twoFactorApp } from '../two-factor/setup';

describe('A040: using a login challenge as a session or a reset ticket', () => {
  it('is not a session', async () => {
    const t = twoFactorApp();

    await t.enrolled();

    const { challenge } = await t.challenged();
    const asSession = await t.auth.validateRequest({ token: challenge, meta: meta() });

    expect(asSession).toMatchObject({ ok: false, code: 'session_expired' });
  });

  it('is not a reset link or a reset ticket', async () => {
    for (const kind of ['link', 'code'] as const) {
      const t = twoFactorApp({}, { passwordReset: { kind } });

      await t.enrolled();

      const { challenge } = await t.challenged();

      const reset = await t.auth.resetPassword({
        token: challenge,
        password: NEW_PASSWORD,
        meta: meta(),
      });

      expect(reset).toMatchObject({ ok: false, code: 'invalid_token', reason: 'reset_unknown' });
    }
  });

  it('is not an email verification link', async () => {
    const t = twoFactorApp({}, { emailVerification: { kind: 'link' } });
    const { session } = await t.enrolled();
    const { challenge } = await t.challenged();
    const verified = await t.auth.verifyEmailLink({ token: challenge, session, meta: meta() });

    expect(verified).toMatchObject({ ok: false, code: 'invalid_token' });
  });

  it('cannot be logged out or used to list sessions', async () => {
    const t = twoFactorApp();
    const { userId } = await t.enrolled();
    const before = await t.stores.sessions.listByUser(userId);
    const { challenge } = await t.challenged();

    await t.auth.logout({ token: challenge, meta: meta() });
    expect(await t.stores.sessions.listByUser(userId)).toEqual(before);
  });
});
