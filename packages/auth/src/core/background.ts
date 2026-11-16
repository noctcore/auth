/**
 * Work that runs off the response path, such as the lockout notice, so a
 * request answers no slower for a known account. A failure is logged, never
 * thrown: nobody is waiting for it.
 */
import type { Logger } from '../ports/logger';
import { describeError } from '../shared/describe-error';

export function runInBackground(logger: Logger, label: string, task: () => Promise<void>): void {
  void task().catch((error: unknown) => {
    logger.error(`Background task failed: ${label}`, { error: describeError(error) });
  });
}
