// A003: account enumeration by the answer.
//
// An attacker submits a list of addresses to login, sign-up and password reset
// and reads which ones have an account from the answers.
//
// Stopped by: shared/errors.ts (public codes that never name account state),
//   flows/login.ts, flows/register.ts, flows/password-reset-request.ts.
// Learn: Enumeration (/auth/learn/enumeration/)
import { describe, expect, it } from 'vitest';

import { toPublicError } from '../../src';
import { EMAIL, meta, PASSWORD, queued, registered, settled, setup } from './support';

describe('A003: account enumeration by the answer', () => {
  it('answers an unknown address, a wrong password and a malformed address the same', async () => {
    const { auth } = await registered();

    const answers = await Promise.all([
      auth.login({ email: 'nobody@example.com', password: PASSWORD, meta: meta() }),
      auth.login({ email: EMAIL, password: 'wrong passphrase!', meta: meta() }),
      auth.login({ email: 'nope', password: PASSWORD, meta: meta() }),
    ]);

    expect(answers.map((a) => !a.ok && toPublicError(a))).toEqual([
      { code: 'invalid_credentials' },
      { code: 'invalid_credentials' },
      { code: 'invalid_credentials' },
    ]);
  });

  it('answers a taken address exactly like a new one and mails the owner instead', async () => {
    const { auth, mailer, audit } = setup();

    const first = await auth.register({
      email: 'ada@example.com',
      password: PASSWORD,
      meta: meta(),
    });

    await settled();

    const sentBefore = mailer.sent.length;

    const second = await auth.register({
      email: 'ADA@example.com',
      password: 'a different passphrase',
      meta: meta(),
    });

    expect(second).toEqual(first);
    await settled();
    const newMail = mailer.sent.slice(sentBefore);

    expect(newMail.map((m) => m.type)).toEqual(['account-exists']);
    expect(audit.types()).toContain('register.existing');
  });

  it('answers the same for known and unknown addresses and mails only the known one', async () => {
    const t = queued();

    await t.signedInUser(EMAIL);
    const known = await t.auth.requestPasswordReset({ email: EMAIL, meta: meta() });
    const unknown = await t.auth.requestPasswordReset({ email: 'ghost@example.com', meta: meta() });

    expect(known).toEqual(unknown);
    expect(t.jobs).toHaveLength(2);
    await t.drain();

    expect(t.mailer.sent.filter((m) => m.type === 'password-reset').map((m) => m.to)).toEqual([
      EMAIL,
    ]);

    expect(t.audit.events.find((e) => e.type === 'password.reset_request_ignored')?.reason).toBe(
      'unknown_user',
    );
  });
});
