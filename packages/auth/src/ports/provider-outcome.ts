/**
 * What an outside provider check (the captcha verifier, the breach check)
 * reports about each call, so an operator can tell an outage from a
 * misconfiguration. A verifier hands every outcome to an optional `onResult`
 * hook; the hook can log or count it but never change the verdict, and an
 * outcome never carries the token, the password or the secret.
 */
import type { Logger } from './logger';
import { describeError } from '../shared/describe-error';

/**
 * Why a provider could not answer:
 * - `timeout`: no answer within `timeoutMs`;
 * - `network-error`: the request or the body read failed (DNS, TLS, reset);
 * - `http-status`: an answer whose status is not a success (see `status`);
 * - `unparsable-body`: a success status with a body that is not the expected shape;
 * - `provider-error`: the provider answered and said it failed on its side.
 */
export type UnavailableReason =
  'timeout' | 'network-error' | 'http-status' | 'unparsable-body' | 'provider-error';

/** The part of an `unavailable` outcome every provider shares. */
export interface UnavailableOutcome {
  readonly verdict: 'unavailable';
  readonly reason: UnavailableReason;
  /** The HTTP status, set only with `reason: 'http-status'`. */
  readonly status?: number;
}

/**
 * Called once for every outcome. Awaited by nobody: a slow promise does not
 * hold the request up, and its result is ignored. The synchronous part still
 * runs on the request path, so keep it cheap. A throw or a rejection is logged
 * (the message only) and never reaches the flow.
 */
export type OutcomeHook<O> = (outcome: O) => void | Promise<void>;

/** Hands `outcome` to `hook`, logging a throw or a rejection instead of passing it on. */
export function reportOutcome<O>(
  hook: OutcomeHook<O> | undefined,
  outcome: O,
  logger: Logger,
  provider: string,
): void {
  if (!hook) return;

  // Guarded itself: an app logger that throws must not turn a failing hook
  // into a failed request, or into an unhandled rejection.
  const failed = (error: unknown): void => {
    try {
      logger.error('onResult hook failed', { provider, error: describeError(error) });
    } catch {
      // Nowhere left to report it.
    }
  };

  try {
    const pending = hook(outcome);

    if (pending && typeof pending.then === 'function') pending.then(undefined, failed);
  } catch (error) {
    failed(error);
  }
}

/** The cause of a failed fetch or body read: our own timeout, or the network. */
export function failureReason(error: unknown): 'timeout' | 'network-error' {
  // Read `name` off any object: a runtime's DOMException is not always an `Error`.
  let name: unknown;

  try {
    name = typeof error === 'object' && error !== null ? (error as { name?: unknown }).name : '';
  } catch {
    name = '';
  }

  return name === 'TimeoutError' || name === 'AbortError' ? 'timeout' : 'network-error';
}
