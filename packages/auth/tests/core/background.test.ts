// Background tasks: the optional waitUntil hook, timeout and pending cap, and
// flush. Every wait runs on Vitest's fake timers, never the wall clock.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { AuthConfigError, BACKGROUND_METRIC, createAuth, type Logger } from '../../src';
import { BackgroundTasks } from '../../src/core/background';
import { memoryStores, plainHasher, recordingAudit, recordingMailer } from '../../src/testing';

function recorder() {
  const errors: string[] = [];
  const contexts: (Record<string, unknown> | undefined)[] = [];
  const counts: string[] = [];

  const logger: Logger = {
    warn: () => undefined,
    error: (message, context) => {
      errors.push(message);
      contexts.push(context);
    },
  };

  const metrics = {
    count: (name: string, labels?: Readonly<Record<string, string>>) =>
      void counts.push(`${name} ${labels?.['task'] ?? ''} ${labels?.['outcome'] ?? ''}`),
  };

  return { errors, contexts, counts, logger, metrics };
}

/** A task that settles only when told to. */
function deferred() {
  let resolve: () => void = () => undefined;
  let reject: (error: unknown) => void = () => undefined;

  const promise = new Promise<void>((res, rej) => {
    resolve = res;
    reject = rej;
  });

  return { promise, resolve, reject };
}

/** Whether `promise` has settled once queued microtasks have run. */
async function isSettled(promise: Promise<unknown>): Promise<boolean> {
  let settled = false;

  void promise.then(
    () => (settled = true),
    () => (settled = true),
  );

  await vi.advanceTimersByTimeAsync(0);

  return settled;
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('background tasks by default', () => {
  it('starts the task at once, logs a failure and never throws it', async () => {
    const r = recorder();
    const tasks = new BackgroundTasks(r.logger, r.metrics);
    let started = false;

    tasks.run('job', async () => {
      started = true;
      throw new Error('boom');
    });

    expect(started).toBe(true);
    await vi.advanceTimersByTimeAsync(0);
    expect(r.errors).toEqual(['Background task failed: job']);
    expect(tasks.pending).toBe(0);
  });

  it('logs a task that throws before returning a promise, like one that rejects', async () => {
    const r = recorder();
    const tasks = new BackgroundTasks(r.logger, r.metrics);

    tasks.run('sync', () => {
      throw new Error('at once');
    });

    await vi.advanceTimersByTimeAsync(0);
    expect(r.errors).toEqual(['Background task failed: sync']);
  });

  it('flushes: resolves once the tasks started before the call settle, and never rejects', async () => {
    const r = recorder();
    const tasks = new BackgroundTasks(r.logger, r.metrics);
    const first = deferred();
    const second = deferred();

    tasks.run('a', () => first.promise);
    tasks.run('b', () => second.promise);

    const flushed = tasks.flush();

    expect(await isSettled(flushed)).toBe(false);
    first.resolve();
    expect(await isSettled(flushed)).toBe(false);
    second.reject(new Error('down'));
    expect(await isSettled(flushed)).toBe(true);
    await expect(flushed).resolves.toBeUndefined();
    await expect(tasks.flush()).resolves.toBeUndefined();
  });
});

describe('flush and tasks started while it waits', () => {
  it('waits for a task that another task starts after flush was called', async () => {
    const r = recorder();
    const tasks = new BackgroundTasks(r.logger, r.metrics);
    const parent = deferred();
    const child = deferred();
    let childDone = false;

    tasks.run('parent', async () => {
      await parent.promise;

      tasks.run('child', async () => {
        await child.promise;
        childDone = true;
      });
    });

    const flushed = tasks.flush();

    parent.resolve();
    expect(await isSettled(flushed)).toBe(false);

    child.resolve();
    expect(await isSettled(flushed)).toBe(true);
    expect(childDone).toBe(true);
  });

  it('resolves as soon as a task settles before its timeout, not at the timeout', async () => {
    const r = recorder();
    const tasks = new BackgroundTasks(r.logger, r.metrics, { timeout: '5s' });
    const job = deferred();

    tasks.run('mail', () => job.promise);

    const flushed = tasks.flush();

    await vi.advanceTimersByTimeAsync(1000);
    job.resolve();
    expect(await isSettled(flushed)).toBe(true);
    expect(r.errors).toEqual([]);
  });

  it('puts the task details into every log line about it', async () => {
    const r = recorder();
    const tasks = new BackgroundTasks(r.logger, r.metrics, { maxPending: 1, timeout: '1s' });

    tasks.run('hung', () => new Promise<void>(() => undefined), { userId: 'u1' });
    tasks.run('mail lockout', async () => undefined, { userId: 'u2' });
    await vi.advanceTimersByTimeAsync(1000);

    const failing = new BackgroundTasks(r.logger, r.metrics);

    failing.run(
      'mail verify-email',
      async () => {
        throw new Error('down');
      },
      { userId: 'u3' },
    );

    await vi.advanceTimersByTimeAsync(0);

    expect(r.errors).toEqual([
      'Background task dropped: mail lockout',
      'Background task timed out: hung',
      'Background task failed: mail verify-email',
    ]);

    expect(r.contexts).toEqual([
      { userId: 'u2', pending: 1 },
      { userId: 'u1', timeoutMs: 1000 },
      { userId: 'u3', error: expect.any(String) as unknown },
    ]);
  });
});

describe('waitUntil', () => {
  it('is handed each task as it starts, as a promise that never rejects', async () => {
    const r = recorder();
    const handed: Promise<void>[] = [];
    const tasks = new BackgroundTasks(r.logger, r.metrics, { waitUntil: (p) => handed.push(p) });
    const job = deferred();

    tasks.run('mail', () => job.promise);
    expect(handed).toHaveLength(1);
    expect(await isSettled(handed[0] as Promise<void>)).toBe(false);

    job.reject(new Error('smtp down'));
    await expect(handed[0]).resolves.toBeUndefined();
  });

  it('logs a waitUntil that throws and still runs the task', async () => {
    const r = recorder();
    let ran = false;

    const tasks = new BackgroundTasks(r.logger, r.metrics, {
      waitUntil: () => {
        throw new Error('no request context');
      },
    });

    tasks.run('mail', async () => void (ran = true));
    await vi.advanceTimersByTimeAsync(0);
    expect(ran).toBe(true);
    expect(r.errors).toEqual(['Background waitUntil failed: mail']);

    expect(r.contexts).toEqual([
      { error: expect.stringContaining('no request context') as unknown },
    ]);
  });
});

describe('timeout', () => {
  it('logs and counts a task still running after the timeout, and stops flush waiting on it', async () => {
    const r = recorder();
    const handed: Promise<void>[] = [];

    const tasks = new BackgroundTasks(r.logger, r.metrics, {
      timeout: '5s',
      waitUntil: (p) => handed.push(p),
    });

    tasks.run('mail verify-email', () => new Promise<void>(() => undefined));

    const flushed = tasks.flush();

    await vi.advanceTimersByTimeAsync(4999);
    expect(await isSettled(flushed)).toBe(false);
    expect(r.errors).toEqual([]);

    await vi.advanceTimersByTimeAsync(1);
    expect(await isSettled(flushed)).toBe(true);
    expect(await isSettled(handed[0] as Promise<void>)).toBe(true);
    expect(r.errors).toEqual(['Background task timed out: mail verify-email']);
    expect(r.counts).toEqual([`${BACKGROUND_METRIC} mail verify-email timed_out`]);

    // Not cancelled: it still counts as pending until it settles.
    expect(tasks.pending).toBe(1);
  });

  it('neither logs nor counts a task that settles in time', async () => {
    const r = recorder();
    const tasks = new BackgroundTasks(r.logger, r.metrics, { timeout: '5s' });
    const job = deferred();

    tasks.run('mail', () => job.promise);
    await vi.advanceTimersByTimeAsync(4000);
    job.resolve();
    await vi.advanceTimersByTimeAsync(10_000);
    expect(r.errors).toEqual([]);
    expect(r.counts).toEqual([]);
    expect(tasks.pending).toBe(0);
  });
});

describe('maxPending', () => {
  it('drops a new task while the cap is reached, counting timed-out tasks until they settle', async () => {
    const r = recorder();
    const tasks = new BackgroundTasks(r.logger, r.metrics, { maxPending: 2, timeout: '1s' });
    const hung = [deferred(), deferred()];
    let dropped = false;

    tasks.run('mail', () => (hung[0] as ReturnType<typeof deferred>).promise);
    tasks.run('mail', () => (hung[1] as ReturnType<typeof deferred>).promise);

    // Both time out, but they still hold memory until they settle, so they still count.
    await vi.advanceTimersByTimeAsync(1000);
    tasks.run('mail', async () => void (dropped = true));

    expect(dropped).toBe(false);
    expect(r.errors).toContain('Background task dropped: mail');
    expect(r.counts).toContain(`${BACKGROUND_METRIC} mail dropped`);

    hung[0]?.resolve();
    await vi.advanceTimersByTimeAsync(0);

    let ran = false;

    tasks.run('mail', async () => void (ran = true));
    expect(ran).toBe(true);
  });

  it('does not hand a dropped task to waitUntil', () => {
    const r = recorder();
    const handed: unknown[] = [];

    const tasks = new BackgroundTasks(r.logger, r.metrics, {
      maxPending: 1,
      waitUntil: (p) => handed.push(p),
    });

    tasks.run('a', () => new Promise<void>(() => undefined));
    tasks.run('b', () => new Promise<void>(() => undefined));
    expect(handed).toHaveLength(1);
  });
});

describe('options', () => {
  it('refuses a timeout of zero and a cap that is not a whole number of at least 1', () => {
    const r = recorder();
    const build = (options: object) => () => new BackgroundTasks(r.logger, r.metrics, options);

    expect(BACKGROUND_METRIC).toBe('auth_background_task');
    expect(build({ timeout: 0 })).toThrow('background.timeout must be longer than zero');

    expect(build({ maxPending: 0 })).toThrow(
      'background.maxPending must be a whole number of at least 1',
    );

    expect(build({ timeout: 0 })).toThrow(AuthConfigError);
    expect(build({ timeout: '0ms' })).toThrow(AuthConfigError);
    expect(build({ maxPending: 0 })).toThrow(AuthConfigError);
    expect(build({ maxPending: 1.5 })).toThrow(AuthConfigError);
    expect(build({ maxPending: Number.POSITIVE_INFINITY })).toThrow(AuthConfigError);
    expect(build({ timeout: 1, maxPending: 1 })).not.toThrow();
  });
});

describe('through createAuth', () => {
  const PASSWORD = 'correct horse battery';

  function app(background: object = {}, throttle?: Parameters<typeof createAuth>[0]['throttle']) {
    const mailer = recordingMailer();
    const audit = recordingAudit();
    const r = recorder();

    const auth = createAuth({
      stores: memoryStores(),
      password: { hasher: plainHasher(), breachCheck: false },
      secret: 'test-secret-that-is-at-least-32-bytes-long',
      urls: { resetPassword: (token) => `https://app.example/reset#${token}` },
      mailer,
      logger: r.logger,
      metrics: r.metrics,
      audit,
      background,
      ...(throttle ? { throttle } : {}),
    });

    return { auth, mailer, audit, ...r };
  }

  it('keeps a sign-up mail alive through waitUntil, and auth.flush waits for it', async () => {
    const handed: Promise<void>[] = [];
    const t = app({ waitUntil: (p: Promise<void>) => handed.push(p) });
    const send = deferred();

    t.mailer.send = () => send.promise;

    const answer = await t.auth.register({
      email: 'ada@example.com',
      password: PASSWORD,
      meta: { ip: '203.0.113.1' },
    });

    expect(answer.ok).toBe(true);
    expect(handed.length).toBeGreaterThan(0);

    const flushed = t.auth.flush();

    expect(await isSettled(flushed)).toBe(false);
    send.resolve();
    expect(await isSettled(flushed)).toBe(true);
  });

  it('runs a reset job without enqueue as one task, and flush waits until its send settled', async () => {
    const t = app();

    await t.auth.register({ email: 'ada@example.com', password: PASSWORD, meta: { ip: '1' } });
    await t.auth.flush();

    const send = deferred();
    let delivered = false;

    t.mailer.send = async () => {
      await send.promise;
      delivered = true;
    };

    await t.auth.requestPasswordReset({ email: 'ada@example.com', meta: { ip: '2' } });

    const flushed = t.auth.flush();

    expect(await isSettled(flushed)).toBe(false);
    send.resolve();
    expect(await isSettled(flushed)).toBe(true);
    expect(delivered).toBe(true);
  });

  it('sends a detached reset mail and a lock notice under maxPending: 1, never dropping them', async () => {
    const t = app({ maxPending: 1 }, { lockout: { perAccount: { limit: 2, window: '15m' } } });
    const sent: string[] = [];

    t.mailer.send = async (event) => void sent.push(event.type);

    await t.auth.register({ email: 'ada@example.com', password: PASSWORD, meta: { ip: '1' } });
    await t.auth.flush();
    await t.auth.requestPasswordReset({ email: 'ada@example.com', meta: { ip: '2' } });
    await t.auth.flush();

    for (let i = 0; i < 3; i++) {
      await t.auth.login({
        email: 'ada@example.com',
        password: 'wrong passphrase!',
        meta: { ip: '3' },
      });

      await t.auth.flush();
    }

    expect(sent).toEqual(['verify-email', 'password-reset', 'lockout']);
    expect(t.errors.filter((e) => e.startsWith('Background task dropped'))).toEqual([]);
  });

  it('sends the lock notice even while the audit sink hangs', async () => {
    const t = app({}, { lockout: { perAccount: { limit: 2, window: '15m' } } });
    const sent: string[] = [];

    await t.auth.register({ email: 'ada@example.com', password: PASSWORD, meta: { ip: '1' } });
    await t.auth.flush();
    t.mailer.send = async (event) => void sent.push(event.type);
    // Only the lock's own audit write hangs; the login's writes still land.
    const emit = t.audit.emit.bind(t.audit);

    t.audit.emit = async (event, meta) =>
      event.type === 'account.locked' ? new Promise<never>(() => undefined) : emit(event, meta);

    for (let i = 0; i < 3; i++)
      await t.auth.login({
        email: 'ada@example.com',
        password: 'wrong passphrase!',
        meta: { ip: '3' },
      });

    await vi.advanceTimersByTimeAsync(0);
    expect(sent).toEqual(['lockout']);
  });

  it('turns a hung mailer into logged drops once maxPending sends are waiting, and still answers', async () => {
    const t = app({ maxPending: 2 });

    t.mailer.send = () => new Promise<void>(() => undefined);

    for (let i = 0; i < 4; i++) {
      const answer = await t.auth.register({
        email: `user${i}@example.com`,
        password: PASSWORD,
        meta: { ip: `203.0.113.${i}` },
      });

      expect(answer.ok).toBe(true);
    }

    expect(t.errors.filter((e) => e === 'Background task dropped: mail verify-email')).toHaveLength(
      2,
    );
  });
});
