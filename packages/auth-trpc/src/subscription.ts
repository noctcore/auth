/**
 * Keeps an open subscription from outliving its session.
 *
 * tRPC builds the context once per HTTP request, and a subscription served
 * over SSE (`httpSubscriptionLink`, on by default in `@trpc/server` 11) is
 * one request that stays open until the client leaves or `sse.maxDurationMs`
 * ends it (no default). The middlewares run once, when it opens, so without
 * this a stream opened before a sign-out, a password change or a revocation
 * goes on sending events to that browser.
 *
 * So a session check wraps the subscription's events: before an event leaves,
 * when the last check is older than `revalidateSubscriptions`, the check runs
 * again (the session validated without counting as activity, its user
 * loaded), and a refusal ends the stream in place of the event. tRPC sends
 * it as the stream's error event and the client link closes the
 * subscription. A reconnect is a new request, checked like any other.
 *
 * - An event is not sent once the last check that saw the session live
 *   started longer ago than the bound: it is refused instead. A check counts
 *   from when it started, so a revocation during a slow check is still caught
 *   by the next one. The bound is read on the core's clock (the wall clock
 *   by default), which is not monotonic: a backwards step delays checks.
 * - The cost is one validation (and one user read) per stream per bound, and
 *   only while events flow: an idle stream reads nothing. Its connection
 *   stays open until the next event, the client leaving, or
 *   `sse.maxDurationMs`.
 * - Ending the stream returns the procedure's own iterator, so its `finally`
 *   runs, as it does when the client leaves.
 * - An observable is read as an async iterable, as tRPC's SSE handler reads
 *   it.
 * - Two session checks on one procedure (`authed` and `role`) wrap once.
 */
import { isObservable, observableToAsyncIterable } from '@trpc/server/observable';
import type { Clock } from '@noctcore/auth';

/** What wrapping needs: when to check, and the check, which throws to end the stream. */
export interface Revalidation {
  /** Milliseconds a check stays good for; 0 checks before every event. */
  readonly every: number;
  readonly clock: Clock;
  /** When the session was last checked, on `clock`. */
  readonly checkedAt: number;
  /** Throws (a refusal) when the session no longer passes. */
  readonly check: () => Promise<void>;
  /** Aborts when the client leaves; ends an observable's subscription. */
  readonly signal: AbortSignal | undefined;
}

const wrapped = new WeakSet<object>();

const isAsyncIterable = (value: unknown): value is AsyncIterable<unknown> =>
  typeof value === 'object' &&
  value !== null &&
  typeof (value as Partial<AsyncIterable<unknown>>)[Symbol.asyncIterator] === 'function';

async function* revalidated(
  source: AsyncIterable<unknown>,
  revalidation: Revalidation,
): AsyncGenerator<unknown, void> {
  const { every, clock, check } = revalidation;
  let checkedAt = revalidation.checkedAt;

  // `for await` returns the source's iterator when this ends, by a refusal or
  // because the consumer stopped reading.
  for await (const value of source) {
    const now = clock.now();

    if (now - checkedAt >= every) {
      // The check may read the store at any moment until it returns, so the
      // session is only known live as of when it started.
      await check();
      checkedAt = now;
    }

    yield value;
  }
}

/**
 * The middleware result with the subscription's events behind the check.
 * Anything else (a refused call, a value tRPC will refuse itself) is returned
 * as it is.
 */
export function revalidateSubscription<TResult>(
  result: TResult,
  revalidation: Revalidation,
): TResult {
  const found = result as { ok?: unknown; data?: unknown };

  if (found.ok !== true) return result;

  const { data } = found;

  const source = isObservable(data)
    ? // tRPC and nestjs-trpc pass the call's signal; the fresh one is a guard
      // for a caller that does not, and the iterator still unsubscribes when returned.
      observableToAsyncIterable(data, revalidation.signal ?? new AbortController().signal)
    : data;

  if (!isAsyncIterable(source) || wrapped.has(source)) return result;

  const guarded = revalidated(source, revalidation);

  wrapped.add(guarded);

  return { ...found, data: guarded } as TResult;
}
