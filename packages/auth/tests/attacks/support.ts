// Shared setup for the attack suite: an app with a registered account, a reset
// queue that is drained by hand, and a recorder for every store call and every
// password verify, the two things a timing attack measures.
import type { PasswordResetJob } from '../../src';
import type { PasswordHasher } from '../../src/password/hasher';
import { plainHasher } from '../../src/testing';
import { meta, PASSWORD, setup } from '../flows/setup';

export { meta, NEW_PASSWORD, PASSWORD, SECRET, setup } from '../flows/setup';

export const EMAIL = 'ada@example.com';

export const tokenOf = (url: string | undefined) => (url ?? '').split('#')[1] ?? '';

/** An app with `EMAIL` registered (not signed in). */
export async function registered(overrides: Parameters<typeof setup>[0] = {}) {
  const env = setup(overrides);

  await env.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });

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
  tokens: ['put', 'find', 'findByUser', 'consume', 'incrementAttempts', 'deleteByUser'],
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
