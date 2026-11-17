// A019: two spellings of one address, or one spelling of two.
//
// An attacker registers or resets with another spelling of the victim's address
// (case, surrounding space) to get a second account, or uses a Unicode look-alike
// that case folding would merge into the victim's account.
//
// Stopped by: shared/email.ts: one ASCII-lowercased spelling per address, every non-ASCII
//   character refused. Property tests: tests/property/email.property.test.ts.
// Learn: Enumeration (/auth/learn/enumeration/); Security defaults (/auth/security/)
import { describe, expect, it } from 'vitest';

import { normalizeEmail } from '../../src/shared/email';
import { meta, PASSWORD, setup } from './support';

describe('A019: two spellings of one address, or one spelling of two', () => {
  it('gives every case and padding variant of an address one spelling', () => {
    const variants = [
      'ada@example.com',
      'ADA@EXAMPLE.COM',
      '  Ada@Example.com ',
      'aDa@exAmple.cOm\t',
    ];

    expect(new Set(variants.map(normalizeEmail))).toEqual(new Set(['ada@example.com']));
  });

  it('refuses look-alikes that Unicode case folding would merge into an ASCII address', () => {
    // KELVIN SIGN lowercases to "k"; a dotted capital I lowercases to "i" plus a combining dot.
    for (const lookAlike of [
      '\u212Aate@example.com',
      'b\u0130ll@example.com',
      'ada@ex\u0430mple.com',
    ])
      expect(normalizeEmail(lookAlike)).toBeNull();
  });

  it('treats a sign-up with another spelling of a taken address as the taken address', async () => {
    const env = setup();

    await env.auth.register({ email: 'kate@example.com', password: PASSWORD, meta: meta() });
    await env.auth.register({ email: ' KATE@example.com', password: PASSWORD, meta: meta() });

    const folded = await env.auth.register({
      email: '\u212Aate@example.com',
      password: PASSWORD,
      meta: meta(),
    });

    expect(env.mailer.sent.map((m) => m.type)).toEqual(['verify-email', 'account-exists']);
    expect(!folded.ok && folded.code).toBe('invalid_email');
  });
});
