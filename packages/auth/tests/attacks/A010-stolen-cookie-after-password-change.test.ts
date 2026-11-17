// A010: a stolen session cookie outliving a password change.
//
// An intruder holds a session cookie; the owner changes or resets the password,
// but the intruder stays signed in.
//
// Stopped by: flows/password-change.ts and flows/password-reset.ts (revoke every session
//   after the new hash is written), session/session-manager.ts (revokeAll).
// Learn: Password reset (/auth/learn/password-reset/), Sessions and expiry (/auth/learn/sessions-and-expiry/)
import { describe, expect, it } from 'vitest';

import { EMAIL, linkFor, meta, NEW_PASSWORD, PASSWORD, queued, setup } from './support';

describe('A010: a stolen session cookie outliving a password change', () => {
  it('ends every other session when the owner changes the password, and keeps the current one', async () => {
    const env = setup();
    const laptop = await env.signedInUser(EMAIL);

    const stolen = await env.auth.login({
      email: EMAIL,
      password: PASSWORD,
      meta: meta('198.51.100.2'),
    });

    if (!stolen.ok || stolen.value.kind !== 'session') throw new Error('second login failed');

    const result = await env.auth.changePassword({
      session: laptop.session,
      currentPassword: PASSWORD,
      newPassword: NEW_PASSWORD,
      meta: meta(),
    });

    if (!result.ok) throw new Error(result.reason);

    expect(await env.sessionOf(stolen.value.session.token)).toBeNull();
    expect(await env.sessionOf(laptop.token)).toBeNull();
    expect(await env.sessionOf(result.value.token)).not.toBeNull();
    expect(env.mailer.last('password-changed')?.to).toBe(EMAIL);

    expect((await env.auth.login({ email: EMAIL, password: NEW_PASSWORD, meta: meta() })).ok).toBe(
      true,
    );
  });

  it('sets the password, ends every session, mails the owner and marks the address verified', async () => {
    const t = queued();
    const { token, session } = await t.signedInUser(EMAIL);
    const link = await linkFor(t);

    expect(
      await t.auth.resetPassword({ token: link, password: NEW_PASSWORD, meta: meta() }),
    ).toEqual({ ok: true, value: undefined });

    expect(await t.sessionOf(token)).toBeNull();
    expect(t.mailer.last('password-changed')?.to).toBe(EMAIL);
    expect((await t.stores.users.findById(session.userId))?.emailVerified).toBe(true);
    expect((await t.auth.login({ email: EMAIL, password: PASSWORD, meta: meta() })).ok).toBe(false);

    expect((await t.auth.login({ email: EMAIL, password: NEW_PASSWORD, meta: meta() })).ok).toBe(
      true,
    );
  });
});
