// A020: exhausting the server with oversized passwords.
//
// An attacker sends a megabyte password so every attempt makes the server hash
// it, or uses sign-up to store one.
//
// Stopped by: password/policy.ts (a maximum length), password/verify.ts (an oversized input
//   is verified as an empty string against the dummy hash), flows/register.ts.
// Learn: Passwords (/auth/learn/passwords/)
import { describe, expect, it } from 'vitest';

import { countingHasher, EMAIL, meta, PASSWORD, registered, setup } from './support';

describe('A020: exhausting the server with oversized passwords', () => {
  it('refuses a password longer than the policy without hashing it', async () => {
    const { auth } = await registered();
    const result = await auth.login({ email: EMAIL, password: 'x'.repeat(10_000), meta: meta() });

    expect(!result.ok && result.code).toBe('invalid_credentials');
  });

  it('refuses short, overlong and breached passwords before touching the user store', async () => {
    const { auth, stores } = setup({
      password: {
        hasher: (await import('../../src/testing')).plainHasher(),
        breachCheck: async (pw) => (pw === 'password1234567' ? 'breached' : 'clean'),
      },
    });

    const short = await auth.register({ email: 'a@example.com', password: 'short', meta: meta() });

    const long = await auth.register({
      email: 'b@example.com',
      password: 'x'.repeat(300),
      meta: meta(),
    });

    const breached = await auth.register({
      email: 'c@example.com',
      password: 'password1234567',
      meta: meta(),
    });

    expect([short, long, breached].map((r) => !r.ok && r.code)).toEqual([
      'weak_password',
      'password_too_long',
      'breached_password',
    ]);

    expect(await stores.users.findById('1')).toBeNull();
  });

  it('verifies an oversized password as an empty one against the dummy hash, at the normal cost', async () => {
    const { hasher, verified } = countingHasher();
    const env = await registered({ password: { hasher, breachCheck: false } });

    const result = await env.auth.login({
      email: EMAIL,
      password: 'x'.repeat(1_000_000),
      meta: meta(),
    });

    expect(!result.ok && result.code).toBe('invalid_credentials');
    expect(verified).toEqual([0]);
    expect(PASSWORD.length).toBeGreaterThan(0);
  });
});
