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
 * `check` returns the verdict with its cause (`BreachOutcome`), and the
 * optional `onResult` hook gets the same outcome for every call, so an
 * operator can tell a timeout from a changed response format. An outcome never
 * carries the password, its hash or the hash prefix, and the hook cannot
 * change the verdict.
 *
 * Guide: Learn, "Passwords".
 */
import { sha1 } from '@oslojs/crypto/sha1';
import { encodeHexUpperCase } from '@oslojs/encoding';

import type { Logger } from '../ports/logger';
import { silentLogger } from '../ports/logger';
import {
  failureReason,
  reportOutcome,
  type OutcomeHook,
  type UnavailableOutcome,
} from '../ports/provider-outcome';
import { assertFunction, assertPositive, assertString } from '../shared/config-checks';

export type BreachVerdict = 'clean' | 'breached' | 'unavailable';

export type BreachChecker = (password: string) => Promise<BreachVerdict>;

/**
 * A breach check's verdict with its cause. `unavailable` carries a `reason`
 * (and the HTTP `status` for `http-status`); `provider-error` is never used,
 * the range API has no error answer of its own.
 */
export type BreachOutcome = { readonly verdict: 'clean' | 'breached' } | UnavailableOutcome;

export interface PwnedPasswordsChecker extends BreachChecker {
  /** Checks like the function itself, and says why when it cannot answer. */
  check(password: string): Promise<BreachOutcome>;
}

export interface PwnedPasswordsOptions {
  /** Default 3000 ms. */
  readonly timeoutMs?: number;
  readonly fetch?: typeof fetch;
  /** Default `noctcore-auth`. */
  readonly userAgent?: string;
  /** Default the public API. */
  readonly baseUrl?: string;
  /**
   * Called with every outcome (clean, breached and unavailable), to log or
   * count it. Not awaited; it cannot change the verdict, and a throw is
   * logged. Its synchronous part still runs on the request path: keep it cheap.
   */
  readonly onResult?: OutcomeHook<BreachOutcome>;
  /** Where a failing `onResult` is reported. Default silent. */
  readonly logger?: Logger;
}

const RANGE_LINE = /^([0-9A-F]{35}):(\d+)$/u;

/** The options as `pwnedPasswords()` reads them, checked when it is called at startup. */
function assertPwnedPasswordsOptions(options: PwnedPasswordsOptions): void {
  assertPositive('pwnedPasswords: timeoutMs', options.timeoutMs);
  assertFunction('pwnedPasswords: fetch', options.fetch);
  assertString('pwnedPasswords: userAgent', options.userAgent);
  assertString('pwnedPasswords: baseUrl', options.baseUrl);
  assertFunction('pwnedPasswords: onResult', options.onResult);
}

export function pwnedPasswords(options?: PwnedPasswordsOptions | null): PwnedPasswordsChecker {
  // A default parameter replaces only undefined: null gives the defaults too.
  options ??= {};

  assertPwnedPasswordsOptions(options);

  const timeoutMs = options.timeoutMs ?? 3000;
  const doFetch = options.fetch ?? globalThis.fetch;
  const userAgent = options.userAgent ?? 'noctcore-auth';
  const baseUrl = options.baseUrl ?? 'https://api.pwnedpasswords.com/range/';
  const logger = options.logger ?? silentLogger;
  const { onResult } = options;

  async function lookup(password: string): Promise<BreachOutcome> {
    const digest = encodeHexUpperCase(sha1(new TextEncoder().encode(password)));
    const prefix = digest.slice(0, 5);
    const suffix = digest.slice(5);
    let body: string;

    try {
      const response = await doFetch(`${baseUrl}${prefix}`, {
        headers: { 'Add-Padding': 'true', 'User-Agent': userAgent },
        signal: AbortSignal.timeout(timeoutMs),
      });

      if (!response.ok)
        return { verdict: 'unavailable', reason: 'http-status', status: response.status };

      body = await response.text();
    } catch (error) {
      return { verdict: 'unavailable', reason: failureReason(error) };
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
      if (!match) return { verdict: 'unavailable', reason: 'unparsable-body' };
      // Count 0 is padding, never a breach.
      if (match[1] === suffix && Number(match[2]) > 0) breached = true;
    }

    return { verdict: breached ? 'breached' : 'clean' };
  }

  async function check(password: string): Promise<BreachOutcome> {
    // Frozen, so a hook that writes to it cannot change what the caller reads.
    const outcome = Object.freeze(await lookup(password));

    reportOutcome(onResult, outcome, logger, 'pwned-passwords');

    return outcome;
  }

  return Object.assign(async (password: string) => (await check(password)).verdict, { check });
}
