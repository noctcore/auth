import { createAuth, type AuthConfig, type AuthPlugin, type RequestMeta } from '../../src';
import type { AuthUser, StoredSession } from '../../src/ports/stores';
import {
  manualClock,
  memoryStores,
  plainHasher,
  recordingAudit,
  recordingMailer,
} from '../../src/testing';

export const SECRET = 'test-secret-that-is-at-least-32-bytes-long';
export const PASSWORD = 'correct horse battery';
export const NEW_PASSWORD = 'another long passphrase';

// Taken now, before a test can swap in fake timers.
const realSetImmediate = globalThis.setImmediate;

/**
 * Lets work the flows started off the response path finish: sign-up's
 * verification mail and audit event, a taken address's notice. The in-memory
 * stores settle on microtasks, which all run before the next macrotask.
 */
export function settled(): Promise<void> {
  return new Promise((resolve) => realSetImmediate(resolve));
}

export function meta(ip = '203.0.113.7'): RequestMeta {
  return { ip, userAgent: 'vitest', origin: 'https://app.example' };
}

type Overrides = Partial<
  Omit<AuthConfig<AuthUser, Record<string, never>, readonly AuthPlugin[]>, 'stores' | 'mailer'>
>;

export function setup(overrides: Overrides = {}) {
  const clock = manualClock(Date.UTC(2026, 0, 1));
  const stores = memoryStores(clock);
  const mailer = recordingMailer();
  const audit = recordingAudit();

  const auth = createAuth({
    stores,
    password: { hasher: plainHasher(), breachCheck: false },
    secret: SECRET,
    urls: {
      resetPassword: (token) => `https://app.example/reset#${token}`,
      verifyEmail: (token) => `https://app.example/verify#${token}`,
    },
    mailer,
    audit,
    clock,
    ...overrides,
  } as AuthConfig<AuthUser, Record<string, never>, readonly AuthPlugin[]>);

  /** Registers, verifies and signs in a user; returns the session and its token. */
  async function signedInUser(email = 'ada@example.com', ip = '203.0.113.7') {
    const registered = await auth.register({ email, password: PASSWORD, meta: meta(ip) });

    if (!registered.ok) throw new Error(`register failed: ${registered.reason}`);

    await settled();

    const login = await auth.login({ email, password: PASSWORD, meta: meta(ip) });

    if (!login.ok || login.value.kind !== 'session') throw new Error('login failed');

    return {
      token: login.value.session.token,
      session: login.value.session.session as StoredSession<Record<string, never>>,
    };
  }

  async function sessionOf(token: string) {
    const result = await auth.validateRequest({ token, meta: meta() });

    return result.ok ? result.value : null;
  }

  return { auth, clock, stores, mailer, audit, signedInUser, sessionOf };
}
