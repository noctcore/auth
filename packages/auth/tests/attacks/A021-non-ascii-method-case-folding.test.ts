// A021: passing an unsafe request as a safe method through Unicode case folding.
//
// The CSRF checks let GET, HEAD and OPTIONS through without looking at the
// origin. They compared the method after `toUpperCase()`, which folds some
// non-ASCII letters into ASCII ones: LATIN SMALL LETTER LONG S becomes "S" and
// DOTLESS I becomes "I". So a method spelled `OPTION\u017F` or `GET` with a dotless i
// was treated as safe and skipped the check, while a router matching the method
// some other way could still run a handler for it. Browsers and Node's HTTP
// parser refuse such methods today, so it was not reachable cross-site, but the
// checks must not depend on that.
//
// Stopped by: http/csrf.ts (methods are upper-cased in ASCII only, so any
//   non-ASCII method is unsafe). Found by tests/property/csrf.property.test.ts.
// Learn: CSRF (/auth/learn/csrf/)
import { describe, expect, it } from 'vitest';

import { verifyFetchSite, verifyRequestOrigin } from '../../src/http/csrf';

const FOLDING_SPELLINGS = [
  'OPTION\u017F', // LATIN SMALL LETTER LONG S upper-cases to S
  'option\u017F',
  'get', // control: an ASCII safe method in any case stays safe
  'HEad',
  '\u0131\u0131',
  'OPT\u0131ONS', // DOTLESS I upper-cases to I
  'G\uFF25T', // FULLWIDTH E does not fold; refused either way
];

describe('A021: passing an unsafe request as a safe method through Unicode case folding', () => {
  it('treats a method that only upper-cases to a safe one through non-ASCII letters as unsafe', () => {
    const verdicts = FOLDING_SPELLINGS.map((method) => ({
      method,
      origin: verifyRequestOrigin({
        method,
        origin: 'https://evil.example',
        allowedOrigins: ['https://app.example'],
      }),
      fetchSite: verifyFetchSite({ method, secFetchSite: 'cross-site' }),
    }));

    expect(verdicts).toEqual([
      { method: 'OPTION\u017F', origin: false, fetchSite: false },
      { method: 'option\u017F', origin: false, fetchSite: false },
      { method: 'get', origin: true, fetchSite: true },
      { method: 'HEad', origin: true, fetchSite: true },
      { method: '\u0131\u0131', origin: false, fetchSite: false },
      { method: 'OPT\u0131ONS', origin: false, fetchSite: false },
      { method: 'G\uFF25T', origin: false, fetchSite: false },
    ]);
  });
});
