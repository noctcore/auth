// A090: a lookalike address under the unicode email policy.
//
// With `email.normalize: 'unicode'`, an attacker registers an address that
// renders like the victim's but is made of other code points: a homoglyph
// from another script (Cyrillic `\u0430` for Latin `a`), an invisible character
// (zero-width space, a soft hyphen, a bidi override) or a compatibility form
// (fullwidth letters), or a Latin letter that reads as another Latin letter
// (the dotless `\u0131`, IPA `\u0251` or `\u0261`, an `i` with a combining dot
// above), to pass as the victim to support, to an inviter or in
// an admin list, or to receive mail meant for them.
//
// Stopped by: shared/email.ts: the unicode policy refuses control, format, separator,
//   private-use, unassigned and default-ignorable code points, anything NFKC would change,
//   punycode labels, any part (local part or domain label) that mixes scripts beyond the
//   CJK mixes UTS 39 allows, the dotless i, the IPA Extensions block (U+0250 to U+02AF) and a
//   combining dot above on i or j (also what a capital dotted I lowercases to). There is no
//   UTS 39 confusables (skeleton) check: other same-script lookalikes are accepted. A part written wholly in another script is a different address
//   by design: the verification mail is the check, and THREAT_MODEL.md names the residual risk.
// Learn: Security defaults (/auth/security/)
import { describe, expect, it } from 'vitest';

import { meta, PASSWORD, settled, setup } from './support';

const VICTIM = 'paypal@example.com';

const LOOKALIKES = [
  ['a Cyrillic a in the local part', 'p\u0430ypal@example.com'],
  ['a Greek omicron in the domain', 'paypal@exampl\u03BF.com'],
  ['a zero-width space', 'pay\u200Bpal@example.com'],
  ['a zero-width joiner', 'pay\u200Dpal@example.com'],
  ['a soft hyphen', 'pay\u00ADpal@example.com'],
  ['a right-to-left override', '\u202Epaypal@example.com'],
  ['fullwidth letters', '\uFF50\uFF41ypal@example.com'],
  ['a punycode spelling of a Unicode domain', 'paypal@xn--exmple-cua.com'],
  ['a dotless i in the local part', 'al\u0131ce@example.com'],
  ['a dotless i in the domain', 'paypal@ma\u0131l.com'],
  ['an IPA alpha in the local part', '\u0251lice@example.com'],
  ['an IPA script g in the local part', '\u0261oogle@example.com'],
  ['an IPA alpha in the domain', 'paypal@ex\u0251mple.com'],
  ['an IPA script g in the domain', 'paypal@\u0261oogle.com'],
  ['an i with a combining dot above', 'ali\u0307ce@example.com'],
  ['a capital I with dot above, which lowercases to i and a dot', 'AL\u0130CE@example.com'],
  ['a j with a combining dot above in the domain', 'paypal@j\u0307obs.com'],
  ['an i with a dot above behind another mark', 'ali\u0323\u0307ce@example.com'],
] as const;

describe('A090: a lookalike address under the unicode email policy', () => {
  it.each(LOOKALIKES)('refuses %s at sign-up', async (_, email) => {
    const t = setup({ email: { normalize: 'unicode' } });

    await t.auth.register({ email: VICTIM, password: PASSWORD, meta: meta() });

    expect(await t.auth.register({ email, password: PASSWORD, meta: meta() })).toMatchObject({
      ok: false,
      code: 'invalid_email',
    });
  });

  it('refuses every lookalike for an email change and an invitation lookup too', async () => {
    const t = setup({ email: { normalize: 'unicode' } });
    const { session } = await t.signedInUser('owner@example.com');

    for (const [, email] of LOOKALIKES) {
      expect(t.auth.normalizeEmail(email)).toBeNull();
      expect(await t.auth.isAddressHeld(email)).toBe(false);
    }

    const changed = await t.auth.requestEmailChange({
      session,
      newEmail: LOOKALIKES[0][1],
      meta: meta(),
    });

    expect(changed).toMatchObject({ ok: false, code: 'invalid_email' });
  });

  it('keeps a wholly other-script address a different account, proved by its own mailbox', async () => {
    // Every letter Cyrillic: one script, so allowed, and a different mailbox.
    const t = setup({ email: { normalize: 'unicode' } });
    const other = '\u0440\u0430\u0443\u0440\u0430\u04CF@example.com';

    await t.auth.register({ email: VICTIM, password: PASSWORD, meta: meta() });
    await t.auth.register({ email: other, password: PASSWORD, meta: meta() });
    await settled();

    expect(t.mailer.sent.map((m) => [m.type, m.to])).toEqual([
      ['verify-email', VICTIM],
      ['verify-email', other],
    ]);
  });
});
