// A088: reading a password, its hash or the hash prefix out of what the breach check reports.
//
// `pwnedPasswords().check()` and the `onResult` hook say why a check could not
// answer, so an operator can tell a timeout from a changed response format.
// That report goes to app logs and metrics, so it must not become a side
// channel: the password, its SHA-1 and even the five-character prefix sent to
// the range API (which narrows the password to a small set) never appear in an
// outcome, whichever way the check ends, and a hook cannot rewrite the verdict.
//
// Stopped by: password/breach.ts (an outcome holds only the verdict, the
//   reason and the HTTP status, and is frozen before the hook sees it),
//   ports/provider-outcome.ts (a failing hook is logged by message only).
// Learn: Passwords (/auth/learn/passwords/)
import { describe, expect, it, vi } from 'vitest';

import { pwnedPasswords } from '../../src/password/breach';

// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
const PASSWORD = 'password';
const PREFIX = '5BAA6';
const SUFFIX = '1E4C9B93F3F0682250B6CF8331B7EE68FD8';

const endings = {
  clean: async () => new Response(`${'0'.repeat(35)}:0`),
  breached: async () => new Response(`${SUFFIX}:3`),
  status: async () => new Response('', { status: 503 }),
  garbage: async () => new Response('<html></html>'),
  timeout: async () => {
    throw new DOMException(`slow ${PREFIX}`, 'TimeoutError');
  },
  network: async () => {
    throw new TypeError(`failed ${PREFIX}${SUFFIX} ${PASSWORD}`);
  },
} satisfies Record<string, typeof fetch>;

describe('A088: reading a password, its hash or the hash prefix out of what the breach check reports', () => {
  it.each(Object.keys(endings) as (keyof typeof endings)[])(
    'keeps the password material out of the %s outcome',
    async (name) => {
      const onResult = vi.fn();
      const outcome = await pwnedPasswords({ fetch: endings[name], onResult }).check(PASSWORD);
      const seen = JSON.stringify([outcome, onResult.mock.calls]).toUpperCase();

      expect(onResult).toHaveBeenCalledTimes(1);
      expect(seen).not.toContain(PASSWORD.toUpperCase());
      expect(seen).not.toContain(PREFIX);
      expect(seen).not.toContain(SUFFIX);
    },
  );

  it('does not let the hook rewrite the verdict', async () => {
    const checker = pwnedPasswords({
      fetch: endings['breached'],
      onResult: (outcome) => {
        (outcome as { verdict: string }).verdict = 'clean';
      },
    });

    expect(await checker(PASSWORD)).toBe('breached');
  });

  it('logs a failing hook by message only', async () => {
    const logger = { warn: vi.fn(), error: vi.fn() };

    const checker = pwnedPasswords({
      fetch: endings['network'],
      logger,
      onResult: () => {
        throw new Error('meter down');
      },
    });

    expect(await checker(PASSWORD)).toBe('unavailable');
    expect(JSON.stringify(logger.error.mock.calls).toUpperCase()).not.toContain(PREFIX);

    expect(logger.error).toHaveBeenCalledWith('onResult hook failed', {
      provider: 'pwned-passwords',
      error: 'meter down',
    });
  });
});
