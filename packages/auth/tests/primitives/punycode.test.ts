// The Punycode decoder behind the unicode email policy's host check: it must
// agree with the runtime's own decoding for every label the URL parser writes,
// and refuse input that is not valid Punycode.
import { domainToUnicode } from 'node:url';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { decodePunycode } from '../../src/shared/punycode';
import { runs } from '../property/runs';

const letter = fc
  .integer({ min: 0xa0, max: 0x2ffff })
  .filter((c) => c < 0xd800 || c > 0xdfff)
  .map((c) => String.fromCodePoint(c));

describe('decodePunycode', () => {
  it('decodes known labels', () => {
    expect(decodePunycode('bcher-kva')).toBe('b\u00FCcher');
    expect(decodePunycode('fsqu00a')).toBe('\u4F8B\u5B50');
    expect(decodePunycode('abc-')).toBe('abc');
  });

  it('refuses input that is not valid Punycode', () => {
    for (const input of ['b\u00FC-kva', 'a!', 'zzzzzzzzzzzzzzzzzzzz', '99999999999'])
      expect(decodePunycode(input)).toBeNull();
  });

  it('agrees with the runtime for every label the URL parser writes', () => {
    fc.assert(
      fc.property(fc.array(letter, { minLength: 1, maxLength: 8 }), (chars) => {
        let label: string;

        try {
          label = new URL(`http://a${chars.join('')}.com/`).hostname.split('.')[0] ?? '';
        } catch {
          return;
        }

        if (!label.startsWith('xn--')) return;

        expect(decodePunycode(label.slice(4))).toBe(domainToUnicode(`${label}.com`).slice(0, -4));
      }),
      runs(),
    );
  });
});
