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

/** What a bounded `flush` round resolves to when its time is up. */
const EXPIRED = Symbol('expired');

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
  readonly #tracked = new Map<Promise<void>, string>();

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

  /**
   * `details` (ids, never user input) go into every log line about the task.
   * An `uncapped` task (an audit write) is never dropped and does not count
   * toward `maxPending`, so a cap that drops mail never drops the audit trail;
   * `timeout`, `waitUntil` and `flush` still cover it.
   */
  run(
    label: string,
    task: () => Promise<void>,
    details?: Readonly<Record<string, string>>,
    options: { readonly uncapped?: boolean } = {},
  ): void {
    const capped = options.uncapped !== true;

    if (capped && this.#running >= this.#maxPending) {
      this.#logger.error(`Background task dropped: ${label}`, {
        ...details,
        pending: this.#running,
      });

      this.#metrics.count(BACKGROUND_METRIC, { task: label, outcome: 'dropped' });

      return;
    }

    if (capped) this.#running += 1;

    const settled = start(task)
      .catch((error: unknown) => {
        this.#logger.error(`Background task failed: ${label}`, {
          ...details,
          error: describeError(error),
        });
      })
      .finally(() => {
        if (capped) this.#running -= 1;
      });

    const tracked =
      this.#timeoutMs === undefined ? settled : this.#withTimeout(label, settled, details);

    this.#tracked.set(tracked, label);
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
   * rejects. Each round waits at most `background.timeout` when one is set.
   *
   * With `timeout`, it gives up after that long in all: whatever is still
   * running is logged as `Background flush stopped waiting`, with the task
   * labels, and left running. Use it on shutdown, where a `send` that never
   * settles must not hold the process forever.
   */
  async flush(options: { readonly timeout?: Duration } = {}): Promise<void> {
    if (options.timeout === undefined) {
      while (this.#tracked.size > 0) await Promise.all([...this.#tracked.keys()]);

      return;
    }

    let timer: ReturnType<typeof setTimeout> | undefined;

    const expired = new Promise<typeof EXPIRED>((resolve) => {
      timer = setTimeout(() => resolve(EXPIRED), toMilliseconds(options.timeout ?? 0));
      (timer as { unref?: () => void }).unref?.();
    });

    try {
      while (this.#tracked.size > 0) {
        const round = await Promise.race([Promise.all([...this.#tracked.keys()]), expired]);

        if (round === EXPIRED) {
          this.#logger.error('Background flush stopped waiting', {
            pending: this.#tracked.size,
            tasks: [...this.#tracked.values()].join(', '),
          });

          return;
        }
      }
    } finally {
      clearTimeout(timer);
    }
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
