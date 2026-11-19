// A089: another spelling of the victim's address under a configured email policy.
//
// With `email.normalize` set to `ascii`, `unicode` or a custom function, an
// attacker signs up, resets or guesses with another spelling of the victim's
// address (uppercase, decomposed accents, a canonically equal sign) to get a
// second account for one mailbox, a reset mailed to an address that is not
// the account's, or a fresh guessing budget per spelling.
//
// Stopped by: shared/email.ts: one normaliser resolved at startup, every policy idempotent
//   (custom ones checked at startup and on every call); core/auth-core.ts: every flow, store
//   write, comparison and counter key goes through `core.normalizeEmail` or `core.parseEmail`;
//   the lint rule in eslint.config.js bans the fixed function inside the flows.
//   Property tests: tests/property/email-policy.property.test.ts.
// Learn: Enumeration (/auth/learn/enumeration/); Security defaults (/auth/security/)
import { describe, expect, it } from 'vitest';

import type { EmailNormalizer } from '../../src';
import { meta, PASSWORD, settled, setup } from './support';

const VICTIM = 'zo\u00EB@b\u00FCcher.de';

const SPELLINGS = [
  'ZO\u00CB@B\u00DCCHER.DE',
  'zoe\u0308@bu\u0308cher.de',
  ' Zoe\u0308@B\u00FCcher.DE ',
];

const lowerNfc: EmailNormalizer = (email) => {
  const value = email.trim().normalize('NFC').toLowerCase().normalize('NFC');

  return /^[^\s,;:<>()"\\[\]@]+@[^\s,;:<>()"\\[\]@]+$/u.test(value) ? value : null;
};

describe('A089: another spelling of the victim address under a configured email policy', () => {
  it.each([['unicode' as const], ['custom' as const]])(
    'gives no second account for any spelling (%s)',
    async (name) => {
      const t = setup({ email: { normalize: name === 'custom' ? lowerNfc : name } });

      await t.auth.register({ email: VICTIM, password: PASSWORD, meta: meta() });

      for (const email of SPELLINGS)
        await t.auth.register({ email, password: 'attacker passphrase', meta: meta() });

      await settled();

      expect(t.mailer.sent.map((m) => m.type)).toEqual([
        'verify-email',
        'account-exists',
        'account-exists',
        'account-exists',
      ]);

      expect(new Set(t.mailer.sent.map((m) => m.to))).toEqual(new Set([VICTIM]));
    },
  );

  it('gives a Greek address one account whether its sigma is typed small, final or capital', async () => {
    const t = setup({ email: { normalize: 'unicode' } });

    await t.auth.register({ email: '\u03B1\u03C3@example.gr', password: PASSWORD, meta: meta() });

    for (const email of ['\u0391\u03A3@example.gr', '\u03B1\u03C2@example.gr'])
      await t.auth.register({ email, password: 'attacker passphrase', meta: meta() });

    await settled();

    expect(t.mailer.sent.map((m) => m.type)).toEqual([
      'verify-email',
      'account-exists',
      'account-exists',
    ]);
  });

  it('mails a reset asked for by another spelling to the address on the account', async () => {
    const t = setup({ email: { normalize: 'unicode' } });

    await t.auth.register({ email: VICTIM, password: PASSWORD, meta: meta() });

    for (const email of SPELLINGS) {
      await t.auth.requestPasswordReset({ email, meta: meta() });
      await settled();
      expect(t.mailer.last('password-reset')?.to).toBe(VICTIM);
    }
  });

  it('counts guesses under every spelling against one budget', async () => {
    const t = setup({ email: { normalize: 'unicode' } });

    await t.auth.register({ email: VICTIM, password: PASSWORD, meta: meta() });

    // Five wrong guesses spread over the spellings use up the per-account budget...
    for (let i = 0; i < 5; i++) {
      const email = SPELLINGS[i % SPELLINGS.length] ?? VICTIM;

      await t.auth.login({ email, password: 'wrong passphrase!', meta: meta('192.0.2.66') });
    }

    // ...so even the right password under yet another spelling is refused from there.
    const next = await t.auth.login({
      email: VICTIM,
      password: PASSWORD,
      meta: meta('192.0.2.66'),
    });

    expect(next.ok).toBe(false);
  });

  it('refuses at startup a custom normaliser whose output drifts on a second pass', () => {
    // Not idempotent: each pass strips one more character, so stored rows stop matching.
    const drifts: EmailNormalizer = (email) => email.trim().slice(1);

    expect(() => setup({ email: { normalize: drifts } })).toThrow(/idempotent/u);
  });
});
