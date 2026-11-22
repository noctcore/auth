// Shared setup for the attack suite: an app with a registered account, a reset
// queue that is drained by hand, and a recorder for every store call and every
// password verify, the two things a timing attack measures.
import { vi } from 'vitest';

import type { AuthMailEvent, PasswordResetJob } from '../../src';
import type { PasswordHasher } from '../../src/password/hasher';
import { plainHasher } from '../../src/testing';
import { meta, PASSWORD, settled, setup } from '../flows/setup';
import { twoFactorApp } from '../two-factor/setup';

export { meta, NEW_PASSWORD, PASSWORD, SECRET, settled, setup } from '../flows/setup';

export const EMAIL = 'ada@example.com';

export const tokenOf = (url: string | undefined) => (url ?? '').split('#')[1] ?? '';

/** An app with `EMAIL` registered (not signed in). */
export async function registered(overrides: Parameters<typeof setup>[0] = {}) {
  const env = setup(overrides);

  await env.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });
  await settled();

  return env;
}

/** An app whose password reset jobs wait in `jobs` until `drain()`. */
export function queued(overrides: Parameters<typeof setup>[0] = {}) {
  const jobs: PasswordResetJob[] = [];

  const t = setup({
    ...overrides,
    passwordReset: { enqueue: async (job) => void jobs.push(job), ...overrides.passwordReset },
  });

  async function drain() {
    while (jobs.length) await t.auth.jobs.processPasswordReset(jobs.shift() as PasswordResetJob);
  }

  return { ...t, jobs, drain };
}

export type Queued = ReturnType<typeof queued>;

/** A two-factor app whose password reset jobs wait until `resetLinkFor` drains them. */
export function queuedTwoFactor() {
  const jobs: PasswordResetJob[] = [];
  const t = twoFactorApp({}, { passwordReset: { enqueue: async (job) => void jobs.push(job) } });

  /** Requests a reset for `email` from `ip`, drains the queue and returns the link's token. */
  async function resetLinkFor(email: string, ip?: string) {
    await t.auth.requestPasswordReset({ email, meta: meta(ip) });

    while (jobs.length) await t.auth.jobs.processPasswordReset(jobs.shift() as PasswordResetJob);

    return tokenOf(t.mailer.last('password-reset')?.url);
  }

  return { ...t, resetLinkFor };
}

export async function requestAndDrain(t: Queued, email = EMAIL) {
  await t.auth.requestPasswordReset({ email, meta: meta() });
  await t.drain();
}

/** Requests a reset link for `EMAIL` and returns its token. */
export async function linkFor(t: Queued) {
  await requestAndDrain(t);

  return tokenOf(t.mailer.last('password-reset')?.url);
}

/** Requests a reset code for `EMAIL` and returns it. */
export async function codeFor(t: Queued) {
  await requestAndDrain(t);

  return t.mailer.last('password-reset-code')?.code ?? '';
}

/** A hasher that counts its verifies and remembers the length of each password it was given. */
export function countingHasher(base: PasswordHasher = plainHasher()) {
  const verified: number[] = [];

  const hasher: PasswordHasher = {
    ...base,
    verify: async (hash, password) => (verified.push(password.length), base.verify(hash, password)),
  };

  return { hasher, verified };
}

/** The methods of each store port, the calls a request makes across the network. */
const PORT_METHODS = {
  users: [
    'findCredentialByEmail',
    'findCredentialById',
    'findById',
    'create',
    'setPasswordHash',
    'markEmailVerified',
  ],
  sessions: ['create', 'get', 'touch', 'delete', 'listByUser', 'getEpoch', 'bumpEpoch'],
  tokens: [
    'put',
    'find',
    'findByUser',
    'consume',
    'incrementAttempts',
    'incrementAttemptsByHash',
    'deleteByUser',
  ],
  counters: ['increment', 'get', 'set', 'decrement', 'reset'],
} as const;

/**
 * Records every call a flow makes through a store port, as `store.method`.
 * Arguments are left out on purpose: a known and an unknown address differ in
 * their keys, and what an observer can time is the sequence of round trips,
 * not their contents.
 */
export function recordStoreCalls(stores: Record<keyof typeof PORT_METHODS, object>): {
  calls: string[];
} {
  const calls: string[] = [];

  for (const [storeName, methods] of Object.entries(PORT_METHODS)) {
    const store = stores[storeName as keyof typeof PORT_METHODS] as Record<string, unknown>;

    for (const method of methods) {
      const original = (store[method] as (...args: unknown[]) => unknown).bind(store);

      store[method] = (...args: unknown[]) => (
        calls.push(`${storeName}.${method}`),
        original(...args)
      );
    }
  }

  return { calls };
}

/** How long, on the fake clock, a flow may take before it counts as held up. */
export const HELD_UP_AFTER_MS = 60_000;

/**
 * Runs `run` on Vitest's fake timers and returns its result, or 'held up' when
 * it has not settled after HELD_UP_AFTER_MS of fake time. No wall-clock wait:
 * the in-memory stores settle on microtasks, which advancing the fake clock
 * drains before it fires the deadline.
 */
export async function onFakeClock<T>(run: () => Promise<T>): Promise<T | 'held up'> {
  vi.useFakeTimers();

  let timer: ReturnType<typeof setTimeout> | undefined;

  try {
    const deadline = new Promise<'held up'>((resolve) => {
      timer = setTimeout(() => resolve('held up'), HELD_UP_AFTER_MS);
    });

    const answer = Promise.race([run(), deadline]);

    await vi.advanceTimersByTimeAsync(HELD_UP_AFTER_MS);

    return await answer;
  } finally {
    clearTimeout(timer);
    vi.useRealTimers();
  }
}

/** Swaps the app's mailer for one that records each hand-off and never settles. */
export function hangMailer(mailer: { send: (event: AuthMailEvent) => Promise<void> }): {
  handed: AuthMailEvent[];
} {
  const handed: AuthMailEvent[] = [];

  mailer.send = (event) => (handed.push(event), new Promise<void>(() => undefined));

  return { handed };
}
