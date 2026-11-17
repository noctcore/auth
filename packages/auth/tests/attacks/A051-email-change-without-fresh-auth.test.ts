// A051: changing the email from a session without a fresh credential proof.
//
// An attacker holding a stolen session cookie, hours after the owner last
// typed the password, moves the account to an address they control and then
// resets the password from it. A session alone must not be enough.
//
// Stopped by: flows/email-change.ts (the request reads the session live and
//   calls `requireFreshAuth`: the last credential proof must be inside
//   `session.freshAuthAge`, 10 minutes by default), flows/password-change.ts
//   (`reauthenticate` is the only way back to a fresh proof, and it needs the password).
// Learn: Email change (/auth/learn/email-change/)
import { describe, expect, it } from 'vitest';

import { meta, PASSWORD, setup } from './support';

describe('A051: changing the email from a session without a fresh credential proof', () => {
  it('refuses a session whose credential proof is older than freshAuthAge, and mails nothing', async () => {
    const t = setup();
    const { session } = await t.signedInUser();

    t.clock.advance(10 * 60_000 + 1);

    const stolen = await t.auth.requestEmailChange({
      session,
      newEmail: 'mallory@example.com',
      meta: meta('198.51.100.66'),
    });

    expect(stolen).toMatchObject({ ok: false, code: 'fresh_auth_required' });
    expect(t.mailer.last('email-change-confirm')).toBeUndefined();

    expect(t.audit.events.at(-1)).toMatchObject({
      type: 'email.change_failed',
      reason: 'stale_authentication',
    });
  });

  it('honours a shorter freshAuthAge', async () => {
    const t = setup({ session: { freshAuthAge: '1m' } });
    const { session } = await t.signedInUser();

    t.clock.advance(60_001);

    expect(
      await t.auth.requestEmailChange({ session, newEmail: 'mallory@example.com', meta: meta() }),
    ).toMatchObject({ ok: false, code: 'fresh_auth_required' });
  });

  it('accepts the request again only after the password is proved anew', async () => {
    const t = setup();
    const { session } = await t.signedInUser();

    t.clock.advance(10 * 60_000 + 1);

    const wrong = await t.auth.reauthenticate({
      session,
      password: 'not the password',
      meta: meta(),
    });

    expect(wrong.ok).toBe(false);

    const fresh = await t.auth.reauthenticate({ session, password: PASSWORD, meta: meta() });

    if (!fresh.ok) throw new Error(fresh.reason);

    expect(
      (
        await t.auth.requestEmailChange({
          session: fresh.value.session,
          newEmail: 'grace@example.com',
          meta: meta(),
        })
      ).ok,
    ).toBe(true);
  });
});
