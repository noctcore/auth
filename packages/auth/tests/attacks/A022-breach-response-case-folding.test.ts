// A022: turning a malformed breach-check response into a verdict through Unicode case folding.
//
// The breach check reads the Pwned Passwords range response line by line and
// treats any line that is not `<35 hex>:<count>` as "unavailable", so an
// error page, a captive portal or a tampered response never decides whether a
// password is breached. Lines were upper-cased with `toUpperCase()` before
// that check, which folds some non-ASCII characters into ASCII ones: the
// ligature U+FB00 becomes "FF". A line spelling hex digits that way passed
// the format check and could match the password's hash suffix.
//
// Stopped by: password/breach.ts (lines are upper-cased in ASCII only, so a
//   non-ASCII character fails the format check).
// Learn: Passwords (/auth/learn/passwords/)
import { describe, expect, it } from 'vitest';

import { pwnedPasswords } from '../../src/password/breach';

// SHA-1 of PASSWORD is E8C59 + this suffix, which contains "FF".
const PASSWORD = 'password-1';
const SUFFIX = '4C3BC504A7F57BFFF4DB7DEA9491C97D893';

const answering = (body: string) =>
  pwnedPasswords({ fetch: async () => new Response(body, { status: 200 }) });

describe('A022: turning a malformed breach-check response into a verdict through Unicode case folding', () => {
  it('answers unavailable for a line that only matches after folding a ligature into FF', async () => {
    const folded = SUFFIX.replace('FF', '\uFB00');

    expect(await answering(`${folded}:12\r\n`)(PASSWORD)).toBe('unavailable');
  });

  it('still reads the real line, in either case, as a breach', async () => {
    expect(await answering(`${SUFFIX}:12\r\n`)(PASSWORD)).toBe('breached');
    expect(await answering(`${SUFFIX.toLowerCase()}:12\r\n`)(PASSWORD)).toBe('breached');
  });
});
