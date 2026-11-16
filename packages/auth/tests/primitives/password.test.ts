import { describe, expect, it, vi } from 'vitest';

import { argon2id, DEFAULT_ARGON2ID, OWASP_ARGON2ID } from '../../src/argon2';
import { AuthConfigError } from '../../src/errors';
import { pwnedPasswords } from '../../src/password/breach';
import { dummyHashFor } from '../../src/password/hasher';
import { checkPasswordPolicy } from '../../src/password/policy';

describe('checkPasswordPolicy', () => {
  it('counts code points of the NFC form', () => {
    // 12 composed characters: passes the default minimum of 12.
    expect(checkPasswordPolicy('é'.repeat(12))).toBe('ok');
    // The same text decomposed is 24 UTF-16 units but still 12 characters after NFC.
    expect(checkPasswordPolicy('é'.repeat(12))).toBe('ok');
    expect(checkPasswordPolicy('short')).toBe('too_short');
    expect(checkPasswordPolicy('x'.repeat(257))).toBe('too_long');
  });

  it('has no composition rules', () => {
    expect(checkPasswordPolicy('all lowercase words here')).toBe('ok');
  });
});

describe('argon2id', () => {
  it('defaults to the stricter of the OWASP and auth guide floors and round-trips', async () => {
    const hasher = argon2id();
    const hash = await hasher.hash('correct horse battery staple');

    expect(hash).toMatch(/^\$argon2id\$v=19\$m=19456,t=3,p=1\$/u);
    expect(await hasher.verify(hash, 'correct horse battery staple')).toBe(true);
    expect(await hasher.verify(hash, 'wrong')).toBe(false);
    expect(hasher.needsRehash(hash)).toBe(false);
    expect(OWASP_ARGON2ID).toEqual({ memoryCost: 19_456, timeCost: 2, parallelism: 1 });
    expect(DEFAULT_ARGON2ID).toEqual({ memoryCost: 19_456, timeCost: 3, parallelism: 1 });
  });

  it('returns false for a malformed stored hash instead of throwing', async () => {
    expect(await argon2id().verify('not-a-hash', 'pw')).toBe(false);
  });

  it('flags hashes made with other parameters for rehash', async () => {
    const old = argon2id({ memoryCost: 8192, timeCost: 1, unsafeAllowWeakParameters: true });
    const hash = await old.hash('pw');

    expect(argon2id().needsRehash(hash)).toBe(true);
    expect(argon2id().needsRehash('$2b$10$bcrypt')).toBe(true);
    // Hashes from apps on the OWASP floor (t=2) upgrade on their next login.
    const floor = await argon2id(OWASP_ARGON2ID).hash('pw');

    expect(argon2id().needsRehash(floor)).toBe(true);
  });

  it('refuses parameters below the OWASP table', () => {
    expect(() => argon2id({ memoryCost: 8192, timeCost: 2 })).toThrow(AuthConfigError);
    expect(() => argon2id({ memoryCost: 47_104, timeCost: 1 })).not.toThrow();
    expect(() => argon2id({ memoryCost: 7168, timeCost: 5 })).not.toThrow();
  });

  it('uses the pepper on both sides', async () => {
    const secret = new TextEncoder().encode('pepper-pepper-pepper');
    const peppered = argon2id({ secret });
    const hash = await peppered.hash('pw');

    expect(await peppered.verify(hash, 'pw')).toBe(true);
    expect(await argon2id().verify(hash, 'pw')).toBe(false);
  });
});

describe('dummyHashFor', () => {
  it('is made by the hasher itself, so its parameters never drift', async () => {
    const hasher = argon2id();
    const dummy = await dummyHashFor(hasher);

    expect(hasher.needsRehash(dummy)).toBe(false);
    expect(await dummyHashFor(hasher)).toBe(dummy);
  });

  it('does not cache a failed computation', async () => {
    let calls = 0;

    const flaky = {
      hash: async () => {
        calls++;

        if (calls === 1) throw new Error('boom');

        return 'h';
      },
      verify: async () => false,
      needsRehash: () => false,
    };

    await expect(dummyHashFor(flaky)).rejects.toThrow('boom');
    await expect(dummyHashFor(flaky)).resolves.toBe('h');
  });
});

describe('pwnedPasswords', () => {
  // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
  const suffix = '1E4C9B93F3F0682250B6CF8331B7EE68FD8';

  const respond = (body: string, status = 200) =>
    vi.fn(async () => new Response(body, { status })) as unknown as typeof fetch;

  it('sends only the five-character prefix with padding requested', async () => {
    const fetch = respond('0000000000000000000000000000000000A:0');

    await pwnedPasswords({ fetch })('password');

    const [url, init] = (fetch as unknown as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];

    expect(url).toBe('https://api.pwnedpasswords.com/range/5BAA6');
    expect((init.headers as Record<string, string>)['Add-Padding']).toBe('true');
  });

  it('reports a listed suffix as breached', async () => {
    expect(await pwnedPasswords({ fetch: respond(`${suffix}:3861493\r\n`) })('password')).toBe(
      'breached',
    );
  });

  it('treats count-0 padding rows as clean', async () => {
    expect(await pwnedPasswords({ fetch: respond(`${suffix}:0`) })('password')).toBe('clean');
  });

  it('fails open on errors, non-OK statuses and malformed bodies', async () => {
    expect(await pwnedPasswords({ fetch: respond('', 503) })('password')).toBe('unavailable');

    expect(
      await pwnedPasswords({ fetch: respond('<html>captive portal</html>') })('password'),
    ).toBe('unavailable');

    const throwing = vi.fn(async () => {
      throw new TypeError('network');
    }) as unknown as typeof fetch;

    expect(await pwnedPasswords({ fetch: throwing })('password')).toBe('unavailable');
  });
});
