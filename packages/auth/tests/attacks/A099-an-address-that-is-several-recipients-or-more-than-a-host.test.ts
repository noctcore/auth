// A099: an address that a mail header reads as several recipients, or whose domain is more than a host.
//
// An attacker signs up with an address an address parser does not read as one
// plain mailbox: a list (`eve,victim@example.com`, `eve;victim@example.com`),
// group syntax (`eve:victim@example.com` delivers to `victim@example.com`), angle
// brackets, a comment the parser strips (`victim@example.com(x)`, the victim's
// mailbox as a separate account), quoting or a domain literal. Or, under the
// unicode policy, a domain the URL parser reads as more than a host name
// (`victim@example.com:25`, `victim@evil.test/x`, `victim@ex%41mple.com`,
// `victim@exa_mple.com`), a domain UTS 46 would remap (an ideographic full stop
// for a dot, a Greek iota subscript, an old Cyrillic letter form) or an IPv4
// address, so one mailbox has spellings treated as different accounts.
//
// Stopped by: shared/email.ts: one rule for every policy, built in and custom: no whitespace,
//   control character or RFC 5322 special besides the one @ (`, ; : < > ( ) " \ [ ]`); the unicode
//   policy takes a domain only when it has no port, path, query, fragment, credentials or
//   percent escape, every label of its ASCII (punycode) form is letters, digits and inner
//   hyphens and decodes back to exactly the label typed (shared/punycode.ts), and its last
//   label is not all digits.
//   Unit tests: tests/primitives/email-policy.test.ts, tests/primitives/punycode.test.ts.
// Learn: Security defaults (/auth/security/)
import { describe, expect, it } from 'vitest';

import type { EmailNormalizer } from '../../src';
import { meta, PASSWORD, settled, setup } from './support';

const SEVERAL_RECIPIENTS = [
  'eve,victim@example.com',
  'eve<victim@example.com',
  'victim@example.com>',
  'eve>victim@example.com',
  'eve;victim@example.com',
  'eve:victim@example.com',
  'victim@example.com(x)',
  '(x)victim@example.com',
  'a"b@example.com',
  'a\\b@example.com',
  'victim@[192.0.2.1]',
];

const MORE_THAN_A_HOST = [
  'victim@example.com:25',
  'victim@evil.test/x',
  'victim@example.com?x',
  'victim@example.com#x',
  'victim@ex%41mple.com',
  'victim@example.com;x',
  'victim@exa_mple.com',
  'victim@-example.com',
  'victim@127.0.0.1',
  'victim@x.example\u3002com',
  'victim@x.\u1FB3\u03B1.com',
  'victim@x.\u1C80\u0430.com',
];

const keepsAsTyped: EmailNormalizer = (email) => {
  const value = email.trim().toLowerCase();

  // Refuses only the quoted local part the startup sample probes.
  return value.includes('@') && !value.startsWith('"') ? value : null;
};

const POLICIES = [
  ['standard', 'standard'],
  ['ascii', 'ascii'],
  ['unicode', 'unicode'],
  ['custom', keepsAsTyped],
] as const;

describe('A099: an address that is several recipients, or a domain that is more than a host', () => {
  it.each(POLICIES)(
    'refuses a recipient list at sign-up and sends nothing (%s)',
    async (_, normalize) => {
      const t = setup({ email: { normalize } });

      // One source address each, so the sign-up rate limit never answers first.
      for (const [i, email] of SEVERAL_RECIPIENTS.entries())
        expect(
          await t.auth.register({ email, password: PASSWORD, meta: meta(`192.0.2.${i + 10}`) }),
        ).toMatchObject({
          ok: false,
          code: 'invalid_email',
        });

      await settled();

      expect(t.mailer.sent).toEqual([]);
    },
  );

  it('refuses a domain that is more than a host under the unicode policy', async () => {
    const t = setup({ email: { normalize: 'unicode' } });

    await t.auth.register({ email: 'victim@example.com', password: PASSWORD, meta: meta() });

    for (const [i, email] of MORE_THAN_A_HOST.entries()) {
      expect(t.auth.normalizeEmail(email)).toBeNull();

      expect(
        await t.auth.register({ email, password: PASSWORD, meta: meta(`192.0.2.${i + 10}`) }),
      ).toMatchObject({
        ok: false,
        code: 'invalid_email',
      });
    }

    await settled();

    expect(t.mailer.sent.map((m) => m.to)).toEqual(['victim@example.com']);
  });
});
