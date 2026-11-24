/**
 * The app's metrics port, made unable to throw into a flow.
 *
 * A counter is a side note. A port that throws (a client not connected yet, a
 * label it refuses) used to throw out of `emit` in the middle of a flow: in a
 * password change or reset that skipped the "password changed" mail and
 * replaced the real outcome with the metrics error, after the sessions were
 * already revoked. Inside a background timer it would have been an uncaught
 * exception. Every count goes through this wrapper instead, and a failure is
 * logged with the counter's name.
 */
import type { Logger, Metrics } from '../ports/logger';
import { describeError } from '../shared/describe-error';

export function guardedMetrics(metrics: Metrics, logger: Logger): Metrics {
  return {
    count(name, labels) {
      try {
        metrics.count(name, labels);
      } catch (error) {
        logger.error('Metrics port failed', { name, error: describeError(error) });
      }
    },
  };
}
