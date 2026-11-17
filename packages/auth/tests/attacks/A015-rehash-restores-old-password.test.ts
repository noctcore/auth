// A015: a login rehash bringing back an old password.
//
// A login that started before a password change finishes its parameter-upgrade
// rehash after the change and writes the old password back.
//
// Stopped by: flows/rehash.ts: the rehash is a compare-and-set on the hash it read
//   (UserStore.setPasswordHash with expected).
// Learn: Passwords (/auth/learn/passwords/)
import { describe, expect, it } from 'vitest';

import { plainHasher } from '../../src/testing';
import { EMAIL, meta, PASSWORD, setup } from './support';

describe('A015: a login rehash bringing back an old password', () => {
  it('probe E: a rehash finishing after a password change cannot bring the old password back', async () => {
    const env = setup({ password: { hasher: plainHasher(1), breachCheck: false } });

    await env.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });
    const user = await env.stores.users.findCredentialByEmail(EMAIL as never);

    if (!user) throw new Error('no user');

    const { createAuth } = await import('../../src');
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => (release = resolve));
    const slow = plainHasher(2);
    // The new-parameter hash stalls until the password change has landed.
    const hasher = { ...slow, hash: async (p: string) => (await gate, slow.hash(p)) };

    const auth = createAuth({
      stores: env.stores,
      password: { hasher, breachCheck: false },
      mailer: env.mailer,
      secret: 'x'.repeat(32),
      urls: { resetPassword: (t) => t },
      audit: env.audit,
      clock: env.clock,
    });

    const login = auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    await new Promise((resolve) => setTimeout(resolve, 10));
    // A password change lands while the rehash is in flight.
    await env.stores.users.setPasswordHash(user.id, 'plain$v1$changed-elsewhere');
    release();
    expect((await login).ok).toBe(true);

    expect((await env.stores.users.findCredentialById(user.id))?.passwordHash).toBe(
      'plain$v1$changed-elsewhere',
    );

    expect(env.audit.types()).not.toContain('password.rehashed');
  });
});
