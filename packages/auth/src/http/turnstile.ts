/**
 * The Cloudflare Turnstile verifier. Besides the token, it can check the
 * `hostname` the token was solved on (`expectedHostnames`) and the `action` it
 * was solved for (`checkAction`), so a token from another site sharing the
 * sitekey, or from another form, is refused. Both checks are opt-in: without
 * them any successful token for the sitekey passes. A provider outage or
 * timeout is `unavailable`, never `pass`.
 *
 * `check` returns the verdict with its cause (`TurnstileOutcome`), and the
 * optional `onResult` hook gets the same outcome for every call, so an operator
 * can tell an outage from a misconfiguration. Neither carries the token or the
 * secret, and the hook cannot change the verdict.
 */
import type { CaptchaDoor, CaptchaVerifier } from '../ports/captcha';
import type { Logger } from '../ports/logger';
import { silentLogger } from '../ports/logger';
import {
  failureReason,
  reportOutcome,
  type OutcomeHook,
  type UnavailableOutcome,
} from '../ports/provider-outcome';

/**
 * Why a token was refused:
 * - `missing-token`: no token, so the provider was not called;
 * - `token-too-long`: longer than Turnstile issues, so the provider was not called;
 * - `provider-refused`: siteverify said no (see `errorCodes`: an expired or reused
 *   token, or a wrong secret, which is a misconfiguration);
 * - `hostname-mismatch`: solved on a hostname outside `expectedHostnames`;
 * - `action-mismatch`: solved for another door, with `checkAction`.
 */
export type TurnstileRefusalReason =
  'missing-token' | 'token-too-long' | 'provider-refused' | 'hostname-mismatch' | 'action-mismatch';

interface TurnstileOutcomeBase {
  readonly door: CaptchaDoor;
  /** The `error-codes` siteverify answered with, if any. Empty when it was not called. */
  readonly errorCodes: readonly string[];
}

export type TurnstileOutcome =
  | (TurnstileOutcomeBase & { readonly verdict: 'pass' })
  | (TurnstileOutcomeBase & { readonly verdict: 'reject'; readonly reason: TurnstileRefusalReason })
  | (TurnstileOutcomeBase & UnavailableOutcome);

export interface TurnstileOptions {
  readonly secret: string;
  /** Hostnames the widget may be served from. Strongly recommended. */
  readonly expectedHostnames?: readonly string[];
  /** Require the widget's `action` to equal the door name (`login`, `register`, ...). */
  readonly checkAction?: boolean;
  /** Default 5000 ms. */
  readonly timeoutMs?: number;
  readonly fetch?: typeof fetch;
  /**
   * Called with every outcome (pass, reject and unavailable), to log or count
   * it. Not awaited; it cannot change the verdict, and a throw is logged.
   */
  readonly onResult?: OutcomeHook<TurnstileOutcome>;
  /** Where a failing `onResult` is reported. Default silent. */
  readonly logger?: Logger;
}

export interface TurnstileVerifier extends CaptchaVerifier {
  /** Verifies like `verify`, and says why. */
  check(
    token: string | undefined,
    context: { ip?: string; door: CaptchaDoor },
  ): Promise<TurnstileOutcome>;
}

const SITEVERIFY = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const MAX_TOKEN_LENGTH = 2048;
/** Bounds on the error codes passed on, so a strange answer cannot flood a log line. */
const MAX_ERROR_CODES = 10;
const MAX_ERROR_CODE_LENGTH = 64;

type Verdict = (
  | { readonly verdict: 'pass' }
  | { readonly verdict: 'reject'; readonly reason: TurnstileRefusalReason }
  | UnavailableOutcome
) & { readonly errorCodes?: readonly string[] };

function errorCodesOf(value: unknown): string[] {
  if (!Array.isArray(value)) return [];

  return value
    .filter((code): code is string => typeof code === 'string')
    .slice(0, MAX_ERROR_CODES)
    .map((code) => code.slice(0, MAX_ERROR_CODE_LENGTH));
}

export function turnstile(options: TurnstileOptions): TurnstileVerifier {
  const doFetch = options.fetch ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? 5000;
  const logger = options.logger ?? silentLogger;

  async function siteverify(
    token: string,
    ip: string | undefined,
    door: CaptchaDoor,
  ): Promise<Verdict> {
    const form = new URLSearchParams({ secret: options.secret, response: token });

    if (ip) form.set('remoteip', ip);

    const signal = AbortSignal.timeout(timeoutMs);
    let response: Response;

    try {
      response = await doFetch(SITEVERIFY, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: form,
        signal,
      });
    } catch (error) {
      return { verdict: 'unavailable', reason: failureReason(error) };
    }

    if (!response.ok)
      return { verdict: 'unavailable', reason: 'http-status', status: response.status };

    let data: unknown;

    try {
      data = await response.json();
    } catch (error) {
      // A body that is not JSON is a parse error; a read cut off by the
      // timeout or the network is not the body's fault.
      return {
        verdict: 'unavailable',
        reason: error instanceof SyntaxError ? 'unparsable-body' : failureReason(error),
      };
    }

    if (
      typeof data !== 'object' ||
      data === null ||
      typeof (data as { success?: unknown }).success !== 'boolean'
    ) {
      return { verdict: 'unavailable', reason: 'unparsable-body' };
    }

    const body = data as {
      success: boolean;
      hostname?: unknown;
      action?: unknown;
      'error-codes'?: unknown;
    };

    const errorCodes = errorCodesOf(body['error-codes']);

    if (!body.success) {
      return errorCodes.includes('internal-error')
        ? { verdict: 'unavailable', reason: 'provider-error', errorCodes }
        : { verdict: 'reject', reason: 'provider-refused', errorCodes };
    }

    if (options.expectedHostnames && !options.expectedHostnames.includes(String(body.hostname)))
      return { verdict: 'reject', reason: 'hostname-mismatch', errorCodes };
    if (options.checkAction && body.action !== door)
      return { verdict: 'reject', reason: 'action-mismatch', errorCodes };

    return { verdict: 'pass', errorCodes };
  }

  async function check(
    token: string | undefined,
    context: { ip?: string; door: CaptchaDoor },
  ): Promise<TurnstileOutcome> {
    let verdict: Verdict;

    if (!token) verdict = { verdict: 'reject', reason: 'missing-token' };
    else if (token.length > MAX_TOKEN_LENGTH)
      verdict = { verdict: 'reject', reason: 'token-too-long' };
    else verdict = await siteverify(token, context.ip, context.door);

    // Frozen, so a hook that writes to it cannot change what the caller reads.
    const outcome: TurnstileOutcome = Object.freeze({
      ...verdict,
      door: context.door,
      errorCodes: Object.freeze([...(verdict.errorCodes ?? [])]),
    });

    reportOutcome(options.onResult, outcome, logger, 'turnstile');

    return outcome;
  }

  return {
    check,
    async verify(token, context) {
      return (await check(token, context)).verdict;
    },
  };
}
