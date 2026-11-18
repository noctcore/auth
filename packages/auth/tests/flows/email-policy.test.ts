// `email.normalize` through the real flows: the policy `createAuth` resolved
// is the one register, login, reset, email change, invitations and
// `auth.normalizeEmail` use, and an invalid option stops startup.
import { describe, expect, it } from 'vitest';

import { AuthConfigError, type EmailNormalizer } from '../../src';
import { invitationApp } from '../invitations/setup';
import { meta, PASSWORD, settled, setup } from './setup';

const ZOE_NFC = 'zo\u00EB@b\u00FCcher.de';
const ZOE_NFD = 'zoe\u0308@bu\u0308cher.de';
const ZOE_UPPER_NFD = 'ZOE\u0308@BU\u0308CHER.DE';

describe('the ascii policy in the flows', () => {
  it('answers a non-ASCII address with email_not_ascii at every door that takes one', async () => {
    const t = setup({ email: { normalize: 'ascii' } });

    expect(await t.auth.register({ email: ZOE_NFC, password: PASSWORD, meta: meta() })).toEqual({
      ok: false,
      code: 'email_not_ascii',
      reason: 'email_not_ascii',
    });

    expect(await t.auth.requestPasswordReset({ email: ZOE_NFC, meta: meta() })).toMatchObject({
      code: 'email_not_ascii',
    });

    const { session } = await t.signedInUser('ada@example.com');

    expect(
      await t.auth.requestEmailChange({ session, newEmail: ZOE_NFC, meta: meta() }),
    ).toMatchObject({ code: 'email_not_ascii' });
  });

  it('keeps sign-in uniform: a non-ASCII address is invalid_credentials, the reason audited', async () => {
    const t = setup({ email: { normalize: 'ascii' } });

    expect(await t.auth.login({ email: ZOE_NFC, password: PASSWORD, meta: meta() })).toEqual({
      ok: false,
      code: 'invalid_credentials',
      reason: 'email_not_ascii',
    });

    expect(t.audit.events.at(-1)).toMatchObject({
      type: 'login.failure',
      reason: 'email_not_ascii',
    });
  });

  it('stores and signs in an ASCII address exactly as the default does', async () => {
    const t = setup({ email: { normalize: 'ascii' } });
    const { session } = await t.signedInUser(' Ada@Example.COM ');

    expect((await t.stores.users.findById(session.userId))?.email).toBe('ada@example.com');
  });
});

describe('the unicode policy in the flows', () => {
  it('stores the composed lowercase spelling and signs in with any other', async () => {
    const t = setup({ email: { normalize: 'unicode' } });

    const registered = await t.auth.register({
      email: ZOE_UPPER_NFD,
      password: PASSWORD,
      meta: meta(),
    });

    expect(registered.ok).toBe(true);
    await settled();

    const user = await t.stores.users.findCredentialByEmail(ZOE_NFC as never);

    expect(user?.email).toBe(ZOE_NFC);

    for (const spelling of [ZOE_NFC, ZOE_NFD, ZOE_UPPER_NFD]) {
      const login = await t.auth.login({ email: spelling, password: PASSWORD, meta: meta() });

      expect(login.ok).toBe(true);
    }
  });

  it('treats a second sign-up with another spelling as the taken address', async () => {
    const t = setup({ email: { normalize: 'unicode' } });

    await t.auth.register({ email: ZOE_NFC, password: PASSWORD, meta: meta() });
    await t.auth.register({ email: ZOE_UPPER_NFD, password: PASSWORD, meta: meta() });
    await settled();

    expect(t.mailer.sent.map((m) => m.type)).toEqual(['verify-email', 'account-exists']);
  });

  it('sends the reset for another spelling to the account', async () => {
    const t = setup({ email: { normalize: 'unicode' } });

    await t.auth.register({ email: ZOE_NFC, password: PASSWORD, meta: meta() });
    await settled();
    await t.auth.requestPasswordReset({ email: ZOE_UPPER_NFD, meta: meta() });
    await settled();

    expect(t.mailer.last('password-reset')?.to).toBe(ZOE_NFC);
  });

  it('matches an invitation to the account under any spelling', async () => {
    const t = invitationApp({}, { email: { normalize: 'unicode' } });
    const inviter = await t.user({ canInvite: true });
    const zoe = await t.user({ email: ZOE_NFC });
    const { token } = await t.invite(inviter, ZOE_UPPER_NFD);

    expect(
      (await t.auth.invitations.accept({ session: zoe.session, token, meta: meta() })).ok,
    ).toBe(true);
  });
});

describe('a custom normaliser in the flows', () => {
  // Drops a +tag: a pure, idempotent policy an app may already store under.
  const dropTag: EmailNormalizer = (email) => {
    const value = email.trim().toLowerCase();
    const at = value.lastIndexOf('@');

    return at > 0 ? `${value.slice(0, at).replace(/\+.*$/u, '')}${value.slice(at)}` : null;
  };

  it('is the one the flows and auth.normalizeEmail use', async () => {
    const t = setup({ email: { normalize: dropTag } });

    await t.signedInUser('Ada+News@Example.com');

    const login = await t.auth.login({
      email: 'ada@example.com',
      password: PASSWORD,
      meta: meta(),
    });

    expect(login.ok).toBe(true);
    expect(t.auth.normalizeEmail('ADA+x@example.com')).toBe('ada@example.com');
    expect(t.auth.context.normalizeEmail('ADA+x@example.com')).toBe('ada@example.com');
    expect(t.auth.normalizeEmail('nope')).toBeNull();
  });
});

describe('a custom normaliser that throws after startup', () => {
  it('refuses the address and logs only the error class name', async () => {
    const errors: Array<[string, Record<string, unknown> | undefined]> = [];

    const logger = {
      warn: () => undefined,
      error: (m: string, c?: Record<string, unknown>) => void errors.push([m, c]),
    };

    const picky: EmailNormalizer = (email) => {
      if (email.includes('boom')) throw new TypeError(`cannot read ${email}`);

      return email.includes('@') ? email.trim().toLowerCase() : null;
    };

    const t = setup({ email: { normalize: picky }, logger });

    const login = await t.auth.login({
      email: 'boom@example.com',
      password: PASSWORD,
      meta: meta(),
    });

    expect(login).toMatchObject({
      ok: false,
      code: 'invalid_credentials',
      reason: 'invalid_email',
    });

    expect(errors).toEqual([
      ['email.normalize threw; refusing the address', { errorName: 'TypeError' }],
    ]);
  });
});

describe('the default', () => {
  it('is the standard policy, through auth.normalizeEmail too', () => {
    const t = setup();

    expect(t.auth.normalizeEmail('  Ada@Example.COM ')).toBe('ada@example.com');
    expect(t.auth.normalizeEmail(ZOE_NFC)).toBeNull();
  });
});

describe('startup', () => {
  it('refuses an unknown policy or a custom normaliser that is not idempotent', () => {
    expect(() => setup({ email: { normalize: 'nfc' as never } })).toThrow(AuthConfigError);
    expect(() => setup({ email: { normalize: (email) => `${email}!` } })).toThrow(/idempotent/u);
  });
});
