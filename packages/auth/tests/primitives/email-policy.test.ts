// The email normalisation policies behind `email.normalize`: what each one
// answers for mixed case, internationalised domains, composed and decomposed
// input, confusables and non-ASCII input, and how a custom normaliser is
// checked at startup and on every call.
import { describe, expect, it, vi } from 'vitest';

import {
  normalizeEmail,
  resolveEmailNormalizer,
  type EmailNormalizer,
  type EmailPolicy,
} from '../../src/shared/email';
import { AuthConfigError } from '../../src/shared/errors';

const quiet = () => undefined;
const policy = (name: EmailPolicy | undefined) => resolveEmailNormalizer(name, quiet);

const valueOf = (name: EmailPolicy | undefined, input: unknown) => {
  const verdict = policy(name)(input);

  return verdict.ok ? verdict.email : verdict.reason;
};

// Spelled with escapes so this file stays ASCII and every code point is visible.
const ZOE_NFC = 'zo\u00EB@b\u00FCcher.de';
const ZOE_NFD = 'zoe\u0308@bu\u0308cher.de';
const ZOE_UPPER = 'ZO\u00CB@B\u00DCCHER.DE';
const CYRILLIC_A = '\u0430';
const KELVIN = '\u212A';
const FULLWIDTH_A = '\uFF41';
const ZERO_WIDTH_SPACE = '\u200B';
const RTL_OVERRIDE = '\u202E';

describe('the standard policy (the default)', () => {
  it('is what an unset option resolves to, with the exported function as its twin', () => {
    for (const input of ['  Alice@Example.COM ', ZOE_NFC, 'a@b', 7])
      expect(valueOf(undefined, input)).toBe(valueOf('standard', input));

    expect(normalizeEmail('  Alice@Example.COM ')).toBe('alice@example.com');
    expect(valueOf('standard', ZOE_NFC)).toBe('invalid_email');
  });

  it('keeps punycode domains as they are and refuses their Unicode form', () => {
    expect(valueOf('standard', 'User@XN--BCHER-KVA.de')).toBe('user@xn--bcher-kva.de');
    expect(valueOf('standard', 'user@b\u00FCcher.de')).toBe('invalid_email');
  });
});

describe('the ascii policy', () => {
  it('gives the standard spelling for every ASCII address', () => {
    for (const input of ['  Alice@Example.COM ', 'a.b+c@sub.example.co.uk', 'x@XN--BCHER-KVA.DE'])
      expect(valueOf('ascii', input)).toBe(valueOf('standard', input));
  });

  it('answers a non-ASCII address with its own code, wherever the character is', () => {
    for (const input of [
      ZOE_NFC,
      ZOE_NFD,
      `${CYRILLIC_A}da@example.com`,
      `${KELVIN}ate@example.com`,
      ` ada@ex${CYRILLIC_A}mple.com `,
      `ada${ZERO_WIDTH_SPACE}@example.com`,
    ])
      expect(valueOf('ascii', input)).toBe('email_not_ascii');
  });

  it('still answers invalid_email for an ASCII value that is not an address', () => {
    for (const input of ['', 'no-at', 'a@b', 'a b@c.com', 'a\u0000@b.com', 7])
      expect(valueOf('ascii', input)).toBe('invalid_email');
  });
});

describe('the unicode policy', () => {
  it('lowercases the whole address, domain and local part', () => {
    expect(valueOf('unicode', '  Alice@Example.COM ')).toBe('alice@example.com');
    expect(valueOf('unicode', ZOE_UPPER)).toBe(ZOE_NFC);
  });

  it('gives composed and decomposed input one spelling, the composed one', () => {
    expect(valueOf('unicode', ZOE_NFD)).toBe(ZOE_NFC);
    expect(valueOf('unicode', ZOE_NFC)).toBe(ZOE_NFC);
  });

  it('keeps internationalised domains in Unicode form and refuses their punycode spelling', () => {
    expect(valueOf('unicode', 'Ivan@\u043F\u0440\u0438\u043C\u0435\u0440.\u0420\u0424')).toBe(
      'ivan@\u043F\u0440\u0438\u043C\u0435\u0440.\u0440\u0444',
    );

    expect(valueOf('unicode', 'user@xn--bcher-kva.de')).toBe('invalid_email');
    expect(valueOf('unicode', 'user@XN--BCHER-KVA.de')).toBe('invalid_email');
  });

  it('folds characters that are canonically the same letter', () => {
    // KELVIN SIGN is canonically equivalent to K, so NFC already maps it.
    expect(valueOf('unicode', `${KELVIN}ate@example.com`)).toBe('kate@example.com');
  });

  it('folds the final sigma, so a Greek address has one spelling whatever its case', () => {
    // toLowerCase writes a word-final capital sigma as the final form.
    const plain = '\u03B1\u03C36@example.gr';

    expect(valueOf('unicode', '\u0391\u03A36@EXAMPLE.GR')).toBe(plain);
    expect(valueOf('unicode', '\u03B1\u03C26@example.gr')).toBe(plain);
    expect(valueOf('unicode', plain)).toBe(plain);
  });

  it('keeps a typed final sigma in the domain, as IDNA2008 does, and lowercases a capital one to the plain', () => {
    const final = 'x@\u03B1\u03C2.gr';
    const plain = 'x@\u03B1\u03C3.gr';

    expect(valueOf('unicode', final)).toBe(final);
    expect(valueOf('unicode', plain)).toBe(plain);
    // A capital sigma lowercases to the plain one whatever follows it.
    expect(valueOf('unicode', 'x@\u0391\u03A3.GR')).toBe(plain);
    expect(valueOf('unicode', 'x@\u0391\u03A3\u0391.gr')).toBe('x@\u03B1\u03C3\u03B1.gr');
    // The local part still folds a typed final sigma.
    expect(valueOf('unicode', '\u03B1\u03C2@\u03B1\u03C2.gr')).toBe('\u03B1\u03C3@\u03B1\u03C2.gr');
  });

  it('refuses a part that mixes scripts, the classic homoglyph spoof', () => {
    for (const input of [
      `${CYRILLIC_A}da@example.com`,
      `p${CYRILLIC_A}ypal@example.com`,
      `ada@ex${CYRILLIC_A}mple.com`,
      'ada@\u03BFracle.com',
    ])
      expect(valueOf('unicode', input)).toBe('invalid_email');
  });

  it('allows a single script per part, and the CJK mixes with Latin', () => {
    expect(valueOf('unicode', '\u5C71\u7530@example.jp')).toBe('\u5C71\u7530@example.jp');

    expect(valueOf('unicode', 'taro\u5C71\u7530\u305F\u308D\u3046@example.jp')).not.toBe(
      'invalid_email',
    );

    expect(valueOf('unicode', '\u0438\u0432\u0430\u043D@example.com')).toBe(
      '\u0438\u0432\u0430\u043D@example.com',
    );
  });

  it('refuses invisible, bidi and compatibility characters', () => {
    for (const input of [
      `ada${ZERO_WIDTH_SPACE}@example.com`,
      `ada\u200D@example.com`,
      `${RTL_OVERRIDE}ada@example.com`,
      `${FULLWIDTH_A}da@example.com`,
      '\uFB01le@example.com',
      'ada\u00AD@example.com',
      'ada@exa mple.com',
      'ada\u00A0x@example.com',
    ])
      expect(valueOf('unicode', input)).toBe('invalid_email');
  });

  it('measures the limits in UTF-8 bytes', () => {
    // 32 two-byte letters make a 64-byte local part; 33 make 66.
    expect(valueOf('unicode', `${'\u00E9'.repeat(32)}@example.com`)).not.toBe('invalid_email');
    expect(valueOf('unicode', `${'\u00E9'.repeat(33)}@example.com`)).toBe('invalid_email');
  });

  it('refuses what the standard policy refuses as not an address', () => {
    for (const input of ['', 'no-at', '@example.com', 'a@b', 'a@b.', 'a@@b.com', 'a@.b.com', 7])
      expect(valueOf('unicode', input)).toBe('invalid_email');
  });
});

describe('a custom normaliser', () => {
  const lowerTrim: EmailNormalizer = (email) => {
    const value = email.trim().toLowerCase();

    return value.includes('@') ? value : null;
  };

  it('is used as given, its null answered invalid_email', () => {
    const normalize = resolveEmailNormalizer(lowerTrim, quiet);

    expect(normalize(' Ada@Example.com ')).toEqual({ ok: true, email: 'ada@example.com' });
    expect(normalize('nope')).toEqual({ ok: false, reason: 'invalid_email' });
    expect(normalize(42)).toEqual({ ok: false, reason: 'invalid_email' });
  });

  it('is refused at startup when it is not idempotent', () => {
    const appendsDot: EmailNormalizer = (email) => `${email.trim()}.`;

    expect(() => resolveEmailNormalizer(appendsDot, quiet)).toThrow(/idempotent/u);
  });

  it('is refused at startup when it is not deterministic', () => {
    let calls = 0;
    const flaky: EmailNormalizer = () => `user${String(++calls % 2)}@x.io`;

    expect(() => resolveEmailNormalizer(flaky, quiet)).toThrow(/deterministic/u);
  });

  it('is refused at startup when it throws or returns something unusable', () => {
    const throws: EmailNormalizer = () => {
      throw new Error('boom');
    };

    expect(() => resolveEmailNormalizer(throws, quiet)).toThrow(AuthConfigError);
    expect(() => resolveEmailNormalizer(() => '', quiet)).toThrow(/exactly one @/u);
    expect(() => resolveEmailNormalizer(() => 'a@b\r\nBcc: x@y', quiet)).toThrow(/control/u);

    for (const output of [
      'a@b@c.com',
      '@example.com',
      'ada@',
      'a da@example.com',
      'ada@example.com,eve@example.com',
      'Ada <ada@example.com>',
      `${'a'.repeat(250)}@b.com`,
    ])
      expect(() => resolveEmailNormalizer(() => output, quiet)).toThrow(AuthConfigError);

    expect(() => resolveEmailNormalizer((() => 42) as unknown as EmailNormalizer, quiet)).toThrow(
      AuthConfigError,
    );
  });

  it('is refused at startup when it merges different mailboxes', () => {
    const constant: EmailNormalizer = () => 'everyone@example.com';
    const domainOnly: EmailNormalizer = (email) => {
      const at = email.lastIndexOf('@');

      return at > 0
        ? `user@${email
            .slice(at + 1)
            .trim()
            .toLowerCase()}`
        : null;
    };
    const localOnly: EmailNormalizer = (email) => {
      const at = email.lastIndexOf('@');

      return at > 0 ? `${email.slice(0, at).trim().toLowerCase()}@example.com` : null;
    };

    for (const merges of [constant, domainOnly, localOnly])
      expect(() => resolveEmailNormalizer(merges, quiet)).toThrow(/different mailboxes/u);
  });

  it('may refuse whole domains: only addresses it accepts must stay apart', () => {
    const companyOnly: EmailNormalizer = (email) => {
      const value = email.trim().toLowerCase();

      return value.endsWith('@example.com') && value.indexOf('@') === value.lastIndexOf('@')
        ? value
        : null;
    };

    expect(() => resolveEmailNormalizer(companyOnly, quiet)).not.toThrow();
  });

  it('refuses, and reports, an address it misbehaves on after startup', () => {
    const onError = vi.fn();
    const sample = new Set<string>();

    // Behaves on the startup sample, then breaks on anything new.
    const sneaky: EmailNormalizer = (email) => {
      if (email.startsWith('throw')) throw new Error('later');
      if (email.startsWith('grow')) return `${email}x`;
      if (email.startsWith('ctl')) return 'a@b\u0000.com';

      sample.add(email);

      return lowerTrim(email);
    };

    const normalize = resolveEmailNormalizer(sneaky, onError);

    expect(sample.size).toBeGreaterThan(0);
    expect(normalize('throw@example.com')).toEqual({ ok: false, reason: 'invalid_email' });
    expect(normalize('grow@example.com')).toEqual({ ok: false, reason: 'invalid_email' });
    expect(normalize('ctl@example.com')).toEqual({ ok: false, reason: 'invalid_email' });
    expect(onError).toHaveBeenCalledTimes(3);

    for (const [message] of onError.mock.calls) expect(message).not.toContain('example.com');

    // A throw is reported by its class name only: its message could quote the address.
    expect(onError).toHaveBeenCalledWith('email.normalize threw; refusing the address', {
      errorName: 'Error',
    });
    expect(JSON.stringify(onError.mock.calls)).not.toContain('later');
  });
});

describe('resolving the option', () => {
  it.each([['lowercase'], [''], [42], [null], [{}]])('refuses %j at startup', (value) => {
    expect(() => resolveEmailNormalizer(value as EmailPolicy, quiet)).toThrow(AuthConfigError);
  });
});
