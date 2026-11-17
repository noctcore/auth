/**
 * Refusing passwords that are already in attackers' wordlists, through Have I
 * Been Pwned's range API with k-anonymity: only the first five hex characters
 * of the password's SHA-1 leave the server, and `Add-Padding` hides the answer
 * size too. The full hash, let alone the password, is never sent.
 *
 * The check FAILS OPEN: when the API cannot answer, the verdict is
 * `unavailable` and the flow accepts the password, logs it and counts it. A
 * breach list being down must not stop anyone from registering.
 *
 * Guide: Learn, "Passwords".
 */
import { sha1 } from '@oslojs/crypto/sha1';
import { encodeHexUpperCase } from '@oslojs/encoding';

export type BreachVerdict = 'clean' | 'breached' | 'unavailable';

export type BreachChecker = (password: string) => Promise<BreachVerdict>;

export interface PwnedPasswordsOptions {
  /** Default 3000 ms. */
  readonly timeoutMs?: number;
  readonly fetch?: typeof fetch;
  /** Default `noctcore-auth`. */
  readonly userAgent?: string;
  /** Default the public API. */
  readonly baseUrl?: string;
}

const RANGE_LINE = /^([0-9A-F]{35}):(\d+)$/u;

export function pwnedPasswords(options: PwnedPasswordsOptions = {}): BreachChecker {
  const timeoutMs = options.timeoutMs ?? 3000;
  const doFetch = options.fetch ?? globalThis.fetch;
  const userAgent = options.userAgent ?? 'noctcore-auth';
  const baseUrl = options.baseUrl ?? 'https://api.pwnedpasswords.com/range/';

  return async (password) => {
    const digest = encodeHexUpperCase(sha1(new TextEncoder().encode(password)));
    const prefix = digest.slice(0, 5);
    const suffix = digest.slice(5);
    let body: string;

    try {
      const response = await doFetch(`${baseUrl}${prefix}`, {
        headers: { 'Add-Padding': 'true', 'User-Agent': userAgent },
        signal: AbortSignal.timeout(timeoutMs),
      });

      if (!response.ok) return 'unavailable';

      body = await response.text();
    } catch {
      return 'unavailable';
    }

    let breached = false;

    for (const raw of body.split(/\r?\n/u)) {
      // ASCII only: toUpperCase() folds some non-ASCII characters into ASCII
      // ones (the ligature U+FB00 becomes "FF"), which would let a malformed
      // line pass the format check below.
      const line = raw.trim().replace(/[a-z]+/gu, (letters) => letters.toUpperCase());

      if (line === '') continue;

      const match = RANGE_LINE.exec(line);

      // An error page served with 200, a captive portal, a changed format: not
      // an answer about this password.
      if (!match) return 'unavailable';
      // Count 0 is padding, never a breach.
      if (match[1] === suffix && Number(match[2]) > 0) breached = true;
    }

    return breached ? 'breached' : 'clean';
  };
}
