// The guard around the app's metrics port: a port that throws, an async port
// that rejects (an unhandled rejection ends a Node process by default), and a
// logger that throws while the failure is reported. None of them may reach a
// flow or a background timer.
import { afterEach, describe, expect, it, vi } from 'vitest';

import { BACKGROUND_METRIC, createAuth, type Logger, type Metrics } from '../../src';
import { guardedMetrics } from '../../src/core/guarded-metrics';
import { memoryStores, plainHasher } from '../../src/testing';

function recordingLogger() {
  const lines: { message: string; context?: Record<string, unknown> | undefined }[] = [];

  const logger: Logger = {
    warn: () => undefined,
    error: (message, context) => void lines.push({ message, context }),
  };

  return { logger, lines };
}

/**
 * A port as an app may write it: TypeScript accepts a `count` that returns a
 * promise as `Metrics` (only this repo's lint rule objects).
 */
const asyncPort = (fail: () => Promise<void>): Metrics => ({
  count: fail as unknown as Metrics['count'],
});

afterEach(() => {
  vi.useRealTimers();
});

describe('guardedMetrics', () => {
  it('logs a port that throws, rejects, or hands back a rejecting thenable, and throws nothing', async () => {
    const { logger, lines } = recordingLogger();

    const ports: Metrics[] = [
      {
        count: () => {
          throw new Error('sync');
        },
      },
      asyncPort(async () => {
        throw new Error('async');
      }),
      {
        count: () =>
          ({
            then: (_: unknown, reject: (error: unknown) => void) => reject(new Error('thenable')),
          }) as unknown as void,
      },
    ];

    for (const port of ports)
      expect(guardedMetrics(port, logger).count('auth_event')).toBeUndefined();

    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(lines).toEqual(
      ['sync', 'async', 'thenable'].map((error) => ({
        message: 'Metrics port failed',
        context: { name: 'auth_event', error },
      })),
    );
  });

  it('ignores a logger that throws while it reports a failed count', async () => {
    const logger: Logger = {
      warn: () => undefined,
      error: () => {
        throw new Error('logger down');
      },
    };

    const sync = guardedMetrics(
      {
        count: () => {
          throw new Error('sync');
        },
      },
      logger,
    );

    const rejecting = guardedMetrics(
      asyncPort(async () => {
        throw new Error('async');
      }),
      logger,
    );

    expect(() => sync.count('auth_event')).not.toThrow();
    expect(() => rejecting.count('auth_event')).not.toThrow();

    // A rejection the guard failed to report would surface here as unhandled.
    await new Promise((resolve) => setTimeout(resolve, 0));
  });

  it('catches an async port in the background timer, where nothing else could', async () => {
    vi.useFakeTimers();

    const { logger, lines } = recordingLogger();

    const auth = createAuth({
      stores: memoryStores(),
      password: { hasher: plainHasher(), breachCheck: false },
      secret: 'test-auth-secret-that-is-32-bytes-or-more',
      urls: { resetPassword: (token) => `https://app.example/reset#${token}` },
      // A mail that never goes out: its task times out in the timer.
      mailer: { send: () => new Promise<void>(() => undefined) },
      logger,
      metrics: asyncPort(async () => {
        throw new Error('statsd down');
      }),
      background: { timeout: '1s' },
    });

    await auth.register({
      email: 'ada@example.com',
      password: 'correct horse battery',
      meta: { ip: '203.0.113.7', userAgent: 'test', origin: 'https://app.example' },
    });

    await vi.advanceTimersByTimeAsync(1000);

    expect(lines.map((l) => l.message)).toContain('Background task timed out: verification mail');

    expect(lines).toContainEqual({
      message: 'Metrics port failed',
      context: { name: BACKGROUND_METRIC, error: 'statsd down' },
    });
  });
});
