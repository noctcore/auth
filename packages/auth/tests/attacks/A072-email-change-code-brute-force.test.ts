// A072: brute forcing the email change code.
//
// The new address gets an 8-digit code. An attacker who started a change to
// an address they do not control (to take over its use, or to make the account
// look verified) guesses the code instead, sequentially or in a parallel burst.
//
// Stopped by: tokens/one-time-tokens.ts (the attempt is counted atomically
//   BEFORE the comparison, 5 by default, and the code dies when the cap is
//   reached; codes are HMACs bound to purpose and user), flows/email-change.ts
//   (the code is checked only for the signed-in user's own pending change; confirming is limited per IP).
// Learn: Email change (/auth/learn/email-change/)
import { describe, expect, it } from 'vitest';

import { meta, setup } from './support';
import { requestCode } from '../flows/email-change-support';

const wrongFor = (code: string, i: number) => {
  const guess = String(i).padStart(8, '0');

  return guess === code ? '99999999' : guess;
};

describe('A072: brute forcing the email change code', () => {
  it('kills the code after 5 wrong guesses, so the right one no longer works', async () => {
    const t = setup();
    const { session } = await t.signedInUser();
    const code = await requestCode(t, session, 'grace@example.com');

    for (let i = 0; i < 5; i++) {
      const guess = await t.auth.confirmEmailChangeCode({
        session,
        code: wrongFor(code, i),
        meta: meta(),
      });

      expect(guess).toMatchObject({ ok: false, code: 'invalid_token' });
    }

    expect(await t.auth.confirmEmailChangeCode({ session, code, meta: meta() })).toMatchObject({
      ok: false,
      code: 'invalid_token',
    });

    expect((await t.stores.users.findById(session.userId))?.email).toBe('ada@example.com');
  });

  it('a parallel burst of 50 guesses gets no more than 5 comparisons', async () => {
    const t = setup({ throttle: { doors: { 'email-change': { limit: 1000, window: '1m' } } } });
    const { session } = await t.signedInUser();
    const code = await requestCode(t, session, 'grace@example.com');

    const burst = await Promise.all(
      Array.from({ length: 50 }, (_, i) =>
        t.auth.confirmEmailChangeCode({ session, code: wrongFor(code, i), meta: meta() }),
      ),
    );

    const reasons = burst.map((r) => (r.ok ? 'ok' : r.reason));

    expect(reasons.filter((r) => r === 'email_change_mismatch').length).toBeLessThanOrEqual(5);
    expect(reasons).not.toContain('ok');
    expect((await t.auth.confirmEmailChangeCode({ session, code, meta: meta() })).ok).toBe(false);
  });

  it('limits confirmation attempts per IP', async () => {
    const t = setup();
    const { session } = await t.signedInUser();
    const results = [];

    for (let i = 0; i < 11; i++)
      results.push(
        await t.auth.confirmEmailChangeCode({ session, code: '12345678', meta: meta() }),
      );

    expect(results.at(-1)).toMatchObject({ ok: false, code: 'rate_limited' });
  });
});
