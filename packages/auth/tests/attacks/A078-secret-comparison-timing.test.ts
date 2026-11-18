// A078: learning a secret from how long its comparison takes.
//
// A comparison that stops at the first byte that differs answers a little
// sooner the less of a guess is right, so an attacker who can time many
// guesses (a CSRF token, a device cookie MAC, a code's HMAC) learns the secret
// byte by byte. Node ships an audited constant-time primitive,
// `crypto.timingSafeEqual`, but it throws on a length mismatch, so using it
// carelessly turns a wrong-length guess into a server error.
//
// Stopped by: crypto/hash.ts (hexDigestsEqual and secretsEqual compare through
//   Node's timingSafeEqual where the runtime has one, found through
//   `process.getBuiltinModule` so other runtimes and bundlers never see
//   node:crypto, and through a JavaScript loop that never stops early
//   everywhere else; a length mismatch is unequal before either runs, so only
//   whether the lengths match shows in the time, and every caller compares
//   fixed-length digests). Unit tests: tests/primitives/hash.test.ts, which
//   runs both paths. The lint rule no-secret-comparison keeps library code on
//   these helpers.
// Learn: Why tokens are hashed (/auth/learn/why-tokens-are-hashed/)
import { timingSafeEqual } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type * as HashModule from '../../src/crypto/hash';

type Hash = typeof HashModule;

/** Loads crypto/hash.ts afresh, with `process.getBuiltinModule` answering `crypto`. */
async function loadWith(crypto: unknown): Promise<Hash> {
  vi.resetModules();

  vi.spyOn(process, 'getBuiltinModule').mockImplementation(((id: string) =>
    id === 'node:crypto' ? crypto : undefined) as typeof process.getBuiltinModule);

  return import('../../src/crypto/hash');
}

/** Every verdict the two helpers give on matching, wrong and wrong-length guesses. */
function verdicts({ hexDigestsEqual, secretsEqual, sha256Hex }: Hash) {
  const digest = sha256Hex('secret');

  return [
    hexDigestsEqual(digest, sha256Hex('secret')),
    hexDigestsEqual(digest, sha256Hex('guess')),
    hexDigestsEqual(digest, digest.slice(0, 32)),
    hexDigestsEqual(digest, `${digest}00`),
    secretsEqual('secret', 'secret'),
    secretsEqual('secret', 'secreT'),
    secretsEqual('secret', 'secret and more'),
  ];
}

const EXPECTED = [true, false, false, false, true, false, false];

afterEach(() => {
  vi.restoreAllMocks();
  vi.resetModules();
});

describe('A078: learning a secret from how long its comparison takes', () => {
  it("compares through node:crypto's timingSafeEqual, and never hands it a length mismatch", async () => {
    const native = vi.fn(timingSafeEqual);
    const hash = await loadWith({ timingSafeEqual: native });

    expect(verdicts(hash)).toEqual(EXPECTED);
    // Five comparisons reach the primitive: two wrong-length hex digests stop
    // at the length check, and secretsEqual always compares two 32-byte hashes.
    expect(native).toHaveBeenCalledTimes(5);

    for (const [a, b] of native.mock.calls) expect(a.byteLength).toBe(b.byteLength);
  });

  it('gives the same verdicts through the JavaScript loop where the runtime has no timingSafeEqual', async () => {
    expect(verdicts(await loadWith(undefined))).toEqual(EXPECTED);
    expect(verdicts(await loadWith({}))).toEqual(EXPECTED);
  });
});
