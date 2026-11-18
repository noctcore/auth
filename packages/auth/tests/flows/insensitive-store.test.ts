// A user store whose lookup by address goes through a case- and
// accent-insensitive collation (MySQL's default utf8mb4_0900_ai_ci behaves
// like this). The core must treat a row whose stored address differs from
// the one asked for as not found, under every policy, so another spelling
// never reaches the account with budgets and keys of its own. The conformance
// case "different spellings must not match" refuses such a store outright.
import { describe, expect, it } from 'vitest';

import type { AuthUser, NormalizedEmail, WithPasswordHash } from '../../src';
import { memoryStores, MemoryUserStore, userStoreConformance } from '../../src/testing';
import { meta, PASSWORD, settled, setup } from './setup';

/** Case-insensitive and accent-insensitive, like an `_ai_ci` collation. */
const fold = (value: string) => value.normalize('NFD').replace(/\p{M}/gu, '').toLowerCase();

class InsensitiveUserStore extends MemoryUserStore {
  private readonly addresses = new Set<string>();

  override async create(input: { email: NormalizedEmail; passwordHash: string }) {
    if ([...this.addresses].some((a) => fold(a) === fold(input.email))) return null;

    const user = await super.create(input);

    if (user) this.addresses.add(input.email);

    return user;
  }

  override async findCredentialByEmail(
    email: NormalizedEmail,
  ): Promise<WithPasswordHash<AuthUser> | null> {
    const stored = [...this.addresses].find((a) => fold(a) === fold(email));

    return stored ? super.findCredentialByEmail(stored as NormalizedEmail) : null;
  }
}

const OWNER = 'zoe@example.com';
// Other mailboxes the collation folds onto the owner's row.
const SPELLINGS = ['zo\u00E9@example.com', 'z\u00F6e@example.com', 'zo\u00EB@example.com'];

function insensitiveApp(normalize?: 'standard' | 'unicode') {
  const users = new InsensitiveUserStore();

  const t = setup({
    ...(normalize ? { email: { normalize } } : {}),
    stores: { ...memoryStores(), users },
  } as Parameters<typeof setup>[0]);

  return { ...t, users };
}

describe('a store that matches addresses case- and accent-insensitively', () => {
  it('does not sign in another spelling, even with the right password', async () => {
    const t = insensitiveApp('unicode');

    await t.signedInUser(OWNER);

    for (const email of SPELLINGS) {
      const login = await t.auth.login({ email, password: PASSWORD, meta: meta() });

      expect(login).toMatchObject({ ok: false, code: 'invalid_credentials' });
    }
  });

  it('keeps the context lookup exact under the default policy too', async () => {
    const t = insensitiveApp();

    await t.signedInUser(OWNER);

    expect(
      await t.users.findCredentialByEmail('ZOE@example.com' as NormalizedEmail),
    ).not.toBeNull();

    expect(
      await t.auth.context.findCredentialByEmail('ZOE@example.com' as NormalizedEmail),
    ).toBeNull();

    expect((await t.auth.context.findCredentialByEmail(OWNER as NormalizedEmail))?.email).toBe(
      OWNER,
    );
  });

  it('mails no reset to the account for another spelling', async () => {
    const t = insensitiveApp('unicode');

    await t.signedInUser(OWNER);

    for (const email of SPELLINGS) await t.auth.requestPasswordReset({ email, meta: meta() });

    await settled();

    expect(t.mailer.sent.filter((m) => m.type === 'password-reset')).toEqual([]);
  });

  it('sends no account-exists notice to the owner for a sign-up under another spelling', async () => {
    const t = insensitiveApp('unicode');

    await t.signedInUser(OWNER);

    const before = t.mailer.sent.length;

    await t.auth.register({ email: SPELLINGS[0] ?? '', password: PASSWORD, meta: meta() });
    await settled();

    expect(t.mailer.sent.slice(before)).toEqual([]);
  });

  it('fails the conformance case for exact lookups', async () => {
    const [exact] = userStoreConformance(new InsensitiveUserStore()).filter(
      (c) => c.name === 'different spellings must not match',
    );

    await expect(exact?.run()).rejects.toThrow(/found/u);
  });
});
