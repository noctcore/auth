/**
 * The app's metrics port, made unable to throw into a flow.
 *
 * A counter is a side note. A port that throws (a client not connected yet, a
 * label it refuses) used to throw out of `emit` in the middle of a flow: in a
 * password change or reset that skipped the "password changed" mail and
 * replaced the real outcome with the metrics error, after the sessions were
 * already revoked. Inside a background timer it would have been an uncaught
 * exception. An async port (`count: async () => ...`) type-checks too, and its
 * rejected promise, left alone, is an unhandled rejection, which ends a Node
 * process by default. Every count goes through this wrapper instead: a throw
 * or a rejection is logged with the counter's name, and a logger that throws
 * while doing so is ignored, so nothing from either port reaches the flow.
 */
import type { Logger, Metrics } from '../ports/logger';
import { describeError } from '../shared/describe-error';

export function guardedMetrics(metrics: Metrics, logger: Logger): Metrics {
  const failed = (name: string, error: unknown) => {
    try {
      logger.error('Metrics port failed', { name, error: describeError(error) });
    } catch {
      // The logger is the last place to report to; nothing is left to tell.
    }
  };

  return {
    count(name, labels) {
      try {
        // The port is typed to return nothing, but an async one returns a promise.
        const result: unknown = metrics.count(name, labels);

        if (isThenable(result))
          Promise.resolve(result).catch((error: unknown) => failed(name, error));
      } catch (error) {
        failed(name, error);
      }
    },
  };
}

function isThenable(value: unknown): value is PromiseLike<unknown> {
  return (
    (typeof value === 'object' || typeof value === 'function') &&
    value !== null &&
    typeof (value as { then?: unknown }).then === 'function'
  );
}
