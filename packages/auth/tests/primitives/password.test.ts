import { describe, expect, it, vi } from 'vitest';

import { argon2id, DEFAULT_ARGON2ID, OWASP_ARGON2ID } from '../../src/password/argon2';
import { AuthConfigError } from '../../src/shared/errors';
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

  describe('outcomes', () => {
    const outcomeOf = (fetch: typeof globalThis.fetch, options = {}) =>
      pwnedPasswords({ fetch, ...options }).check('password');

    it('says clean and breached without a reason', async () => {
      expect(await outcomeOf(respond(`${suffix}:0`))).toEqual({ verdict: 'clean' });
      expect(await outcomeOf(respond(`${suffix}:3`))).toEqual({ verdict: 'breached' });
    });

    it('maps a timeout to timeout', async () => {
      const slow = vi.fn(async () => {
        throw new DOMException('too slow', 'TimeoutError');
      }) as unknown as typeof fetch;

      expect(await outcomeOf(slow)).toEqual({ verdict: 'unavailable', reason: 'timeout' });
    });

    it('maps a failed request to network-error', async () => {
      const down = vi.fn(async () => {
        throw new TypeError('fetch failed');
      }) as unknown as typeof fetch;

      expect(await outcomeOf(down)).toEqual({ verdict: 'unavailable', reason: 'network-error' });
    });

    it('maps a failed body read to network-error, or timeout when it was cut by the timer', async () => {
      const cut = (error: Error) =>
        vi.fn(async () => ({
          ok: true,
          text: async () => {
            throw error;
          },
        })) as unknown as typeof fetch;

      expect(await outcomeOf(cut(new TypeError('terminated')))).toEqual({
        verdict: 'unavailable',
        reason: 'network-error',
      });

      expect(await outcomeOf(cut(new DOMException('slow', 'TimeoutError')))).toEqual({
        verdict: 'unavailable',
        reason: 'timeout',
      });
    });

    it('maps a non-success status to http-status and keeps the code', async () => {
      expect(await outcomeOf(respond('', 503))).toEqual({
        verdict: 'unavailable',
        reason: 'http-status',
        status: 503,
      });

      expect(await outcomeOf(respond('', 429))).toMatchObject({ status: 429 });
    });

    it('maps a body that is not range lines to unparsable-body', async () => {
      expect(await outcomeOf(respond('<html>captive portal</html>'))).toEqual({
        verdict: 'unavailable',
        reason: 'unparsable-body',
      });
    });

    it('keeps the function and check in agreement', async () => {
      const checker = pwnedPasswords({ fetch: respond('', 500) });

      expect(await checker('password')).toBe('unavailable');
    });

    it('hands every outcome to onResult once, frozen, and the hook cannot change the verdict', async () => {
      const seen: unknown[] = [];

      const onResult = vi.fn((outcome: { verdict: string }) => {
        seen.push(outcome);
        (outcome as { verdict: string }).verdict = 'clean';
      });

      const checker = pwnedPasswords({ fetch: respond(`${suffix}:9`), onResult });

      expect(await checker.check('password')).toEqual({ verdict: 'breached' });
      expect(onResult).toHaveBeenCalledTimes(1);
      expect(Object.isFrozen(seen[0])).toBe(true);

      await pwnedPasswords({ fetch: respond('', 500), onResult }).check('password');
      expect(onResult).toHaveBeenCalledTimes(2);
    });

    it('reports a throwing or rejecting hook to the logger and keeps the verdict', async () => {
      const logger = { warn: vi.fn(), error: vi.fn() };

      const throwing = pwnedPasswords({
        fetch: respond(`${suffix}:9`),
        logger,
        onResult: () => {
          throw new Error('meter down');
        },
      });

      expect(await throwing('password')).toBe('breached');

      const rejecting = pwnedPasswords({
        fetch: respond(''),
        logger,
        onResult: () => Promise.reject(new Error('queue full')),
      });

      expect(await rejecting('password')).toBe('clean');
      await new Promise((resolve) => setTimeout(resolve, 0));

      expect(logger.error).toHaveBeenCalledWith('onResult hook failed', {
        provider: 'pwned-passwords',
        error: 'meter down',
      });

      expect(logger.error).toHaveBeenCalledWith('onResult hook failed', {
        provider: 'pwned-passwords',
        error: 'queue full',
      });
    });
  });

  it('uses the global fetch and the public range API when nothing is given', async () => {
    const fetch = respond(`${suffix}:3`);

    vi.stubGlobal('fetch', fetch);

    try {
      expect(await pwnedPasswords()('password')).toBe('breached');

      const [url, init] = (fetch as unknown as ReturnType<typeof vi.fn>).mock.calls[0] as [
        string,
        RequestInit,
      ];

      expect(url).toBe('https://api.pwnedpasswords.com/range/5BAA6');
      expect(init.headers).toMatchObject({ 'User-Agent': 'noctcore-auth' });
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
