// A014: verifying an address with a proof meant for another account or address.
//
// An attacker uses a verification code or link sent to someone else, from their
// own session, or one sent to an address the account no longer has.
//
// Stopped by: flows/email-verification.ts (codes bound to user and purpose, links verified
//   only from a session of the same account, the address re-checked on use).
// Learn: Email verification and account pre-hijacking (/auth/learn/email-verification/)
import { describe, expect, it } from 'vitest';

import { meta, setup } from './support';

describe('A014: verifying an address with a proof meant for another account or address', () => {
  it('accepts the code only from the account it was sent to', async () => {
    const env = setup();
    const ada = await env.signedInUser('ada@example.com');
    const adaCode = env.mailer.last('verify-email')?.code ?? '';
    const eve = await env.signedInUser('eve@example.com', '198.51.100.9');

    const stolen = await env.auth.verifyEmailCode({
      session: eve.session,
      code: adaCode,
      meta: meta(),
    });

    expect(!stolen.ok && stolen.code).toBe('invalid_token');
    expect((await env.stores.users.findById(ada.session.userId))?.emailVerified).toBe(false);
  });

  it('refuses a code mailed to an address the account no longer has', async () => {
    const env = setup();
    const { session } = await env.signedInUser();
    const code = env.mailer.last('verify-email')?.code ?? '';

    await env.stores.users.setEmail(session.userId, 'new@example.com' as never);
    const result = await env.auth.verifyEmailCode({ session, code, meta: meta() });

    expect(!result.ok && result.reason).toBe('verification_address_changed');
  });

  it('verifies only from a signed-in session of the same account, and leaves the link unspent otherwise', async () => {
    const env = setup({ emailVerification: { kind: 'link' } });
    const { token: cookie, session } = await env.signedInUser();
    const eve = await env.signedInUser('eve@example.com', '198.51.100.9');

    const url = env.mailer.sent
      .filter((m) => m.type === 'verify-email' && m.to === 'ada@example.com')
      .at(-1);

    const token = (url?.type === 'verify-email' ? (url.url ?? '') : '').split('#')[1] ?? '';

    const anonymous = await env.auth.verifyEmailLink({ token, session: null, meta: meta() });

    expect(!anonymous.ok && anonymous.reason).toBe('verification_session_required');

    const wrongAccount = await env.auth.verifyEmailLink({
      token,
      session: eve.session,
      meta: meta(),
    });

    expect(!wrongAccount.ok && wrongAccount.reason).toBe('verification_session_required');
    expect((await env.stores.users.findById(session.userId))?.emailVerified).toBe(false);

    const result = await env.auth.verifyEmailLink({ token, session, meta: meta() });

    if (!result.ok || !result.value.session) throw new Error('expected a re-issued session');

    expect((await env.stores.users.findById(session.userId))?.emailVerified).toBe(true);
    expect(await env.sessionOf(cookie)).toBeNull();

    const replay = await env.auth.verifyEmailLink({
      token,
      session: result.value.session.session,
      meta: meta(),
    });

    expect(!replay.ok && replay.code).toBe('invalid_token');
  });
});
