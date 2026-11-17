// A012: account pre-hijacking.
//
// An attacker registers the victim's address first, stays signed in, and waits
// for the real owner to take the account over by proving the mailbox.
//
// Stopped by: flows/password-reset.ts and flows/email-verification.ts (proving the mailbox
//   ends every other session), flows/register.ts (a taken address mails the owner).
// Learn: Email verification and account pre-hijacking (/auth/learn/email-verification/)
import { describe, expect, it } from 'vitest';

import { meta, NEW_PASSWORD, PASSWORD, queued, requestAndDrain, setup, tokenOf } from './support';

describe('A012: account pre-hijacking', () => {
  it("ends a squatter's session when the mailbox owner resets (account pre-hijacking)", async () => {
    const t = queued();
    const squatter = await t.signedInUser('victim@example.com');

    await requestAndDrain(t, 'victim@example.com');

    await t.auth.resetPassword({
      token: tokenOf(t.mailer.last('password-reset')?.url),
      password: NEW_PASSWORD,
      meta: meta(),
    });

    expect(await t.sessionOf(squatter.token)).toBeNull();
  });

  it('verifies the address, ends every other session and re-issues the current one', async () => {
    const env = setup();
    const { token, session } = await env.signedInUser();

    const other = await env.auth.login({
      email: 'ada@example.com',
      password: PASSWORD,
      meta: meta('198.51.100.2'),
    });

    const code = env.mailer.last('verify-email')?.code ?? '';

    const result = await env.auth.verifyEmailCode({ session, code, meta: meta() });

    if (!result.ok || !result.value.session) throw new Error('expected a re-issued session');

    expect((await env.stores.users.findById(session.userId))?.emailVerified).toBe(true);
    expect(await env.sessionOf(token)).toBeNull();

    if (!other.ok || other.value.kind !== 'session') throw new Error('second login failed');

    expect(await env.sessionOf(other.value.session.token)).toBeNull();

    expect(await env.sessionOf(result.value.session.token)).not.toBeNull();
    expect(result.value.session.session.authenticatedAt).toBe(session.authenticatedAt);
  });
});
