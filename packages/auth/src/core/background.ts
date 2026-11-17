/**
 * Work that runs off the response path, such as the lockout notice and every
 * mail, so a request answers no slower for a known account. A failure is
 * logged, never thrown: nobody is waiting for it.
 *
 * By default a task runs detached and nothing waits for it. The app can opt
 * into three things (`createAuth({ background })`):
 *
 * - `waitUntil`: handed each task's promise as it starts, for runtimes that
 *   freeze the instance after the response (Vercel, Cloudflare Workers) and
 *   keep it alive for promises passed to their own `waitUntil`.
 * - `timeout`: a task still running after this is logged and counted as timed
 *   out, and stops holding up `flush` and `waitUntil`. It is not cancelled:
 *   JavaScript cannot stop a promise, so whatever it holds stays in memory
 *   until it settles.
 * - `maxPending`: while this many tasks are still running (timed out or not),
 *   a new task is not started; it is logged and counted as dropped. This is
 *   what bounds memory when a mailer hangs instead of failing.
 *
 * `flush()` resolves once no task is left that has neither settled nor timed
 * out, tasks started while it waits included, for a graceful shutdown.
 *
 * The library's own background work sends its mail inside its task
 * (`AuthCore.deliver`), so a sign-up, a lock notice or a detached reset job is
 * one task with one slot, however many sends it makes.
 *
 * Drops, timeouts and failures go to the configured `logger`. The default
 * logger is silent, so pass one (and `metrics`) to see them.
 */
import type { Logger, Metrics } from '../ports/logger';
import { describeError } from '../shared/describe-error';
import { AuthConfigError } from '../shared/errors';
import { toMilliseconds, type Duration } from '../shared/duration';

export interface BackgroundOptions {
  /**
   * Called with each background task's promise as the task starts. The
   * promise never rejects. Pass your runtime's own, for example
   * `waitUntil` from `@vercel/functions`, or a Worker's `ctx.waitUntil`
   * bound to the current request. Not called for a dropped task.
   */
  readonly waitUntil?: (promise: Promise<void>) => void;
  /** Stop waiting on a task after this long, and log it. Default: no timeout. */
  readonly timeout?: Duration;
  /** Drop new tasks while this many are still running. Default: no cap. */
  readonly maxPending?: number;
}

/** The metric every timed-out or dropped task is counted under, with `task` and `outcome` labels. */
export const BACKGROUND_METRIC = 'auth_background_task';

export class BackgroundTasks {
  readonly #logger: Logger;
  readonly #metrics: Metrics;
  readonly #waitUntil: ((promise: Promise<void>) => void) | undefined;
  readonly #timeoutMs: number | undefined;
  /** `Infinity` when no cap was set. */
  readonly #maxPending: number;
  /** Tasks not settled yet, timed out or not: what `maxPending` counts. */
  #running = 0;
  /** What `flush` waits on: each task until it settles or times out. */
  readonly #tracked = new Set<Promise<void>>();

  constructor(logger: Logger, metrics: Metrics, options: BackgroundOptions = {}) {
    this.#logger = logger;
    this.#metrics = metrics;
    this.#waitUntil = options.waitUntil;
    this.#timeoutMs = options.timeout === undefined ? undefined : toMilliseconds(options.timeout);
    this.#maxPending = options.maxPending ?? Number.POSITIVE_INFINITY;

    if (this.#timeoutMs !== undefined && !(this.#timeoutMs > 0))
      throw new AuthConfigError('background.timeout must be longer than zero');

    const cap = options.maxPending;

    if (cap !== undefined && !(Number.isSafeInteger(cap) && cap >= 1))
      throw new AuthConfigError('background.maxPending must be a whole number of at least 1');
  }

  /** How many tasks are still running, timed out or not. */
  get pending(): number {
    return this.#running;
  }

  /** `details` (ids, never user input) go into every log line about the task. */
  run(label: string, task: () => Promise<void>, details?: Readonly<Record<string, string>>): void {
    if (this.#running >= this.#maxPending) {
      this.#logger.error(`Background task dropped: ${label}`, {
        ...details,
        pending: this.#running,
      });

      this.#metrics.count(BACKGROUND_METRIC, { task: label, outcome: 'dropped' });

      return;
    }

    this.#running += 1;

    const settled = start(task)
      .catch((error: unknown) => {
        this.#logger.error(`Background task failed: ${label}`, {
          ...details,
          error: describeError(error),
        });
      })
      .finally(() => {
        this.#running -= 1;
      });

    const tracked =
      this.#timeoutMs === undefined ? settled : this.#withTimeout(label, settled, details);

    this.#tracked.add(tracked);
    void tracked.finally(() => this.#tracked.delete(tracked));

    if (!this.#waitUntil) return;

    try {
      this.#waitUntil(tracked);
    } catch (error) {
      this.#logger.error(`Background waitUntil failed: ${label}`, { error: describeError(error) });
    }
  }

  /**
   * Resolves once every task has settled or timed out, including tasks started
   * while it waits (by other tasks, or by requests still in flight). Never
   * rejects. Each round waits at most `timeout` when one is set.
   */
  async flush(): Promise<void> {
    while (this.#tracked.size > 0) await Promise.all([...this.#tracked]);
  }

  #withTimeout(
    label: string,
    settled: Promise<void>,
    details: Readonly<Record<string, string>> | undefined,
  ): Promise<void> {
    return new Promise<void>((resolve) => {
      const timer = setTimeout(() => {
        this.#logger.error(`Background task timed out: ${label}`, {
          ...details,
          timeoutMs: this.#timeoutMs,
        });

        this.#metrics.count(BACKGROUND_METRIC, { task: label, outcome: 'timed_out' });
        resolve();
      }, this.#timeoutMs);

      // A timer must not keep a finished process alive on its own.
      (timer as { unref?: () => void }).unref?.();

      void settled.then(() => {
        clearTimeout(timer);
        resolve();
      });
    });
  }
}

/** Calls `task` now (its synchronous part runs before `run` returns); a synchronous throw becomes a rejection. */
async function start(task: () => Promise<void>): Promise<void> {
  await task();
}
