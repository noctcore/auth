// Shared setup for the two-factor tests: an app with the plugin on in-memory
// stores, a test cipher that binds each ciphertext to its user, and helpers
// that walk a user through sign-up, enrollment and the login challenge.
import { decodeBase32IgnorePadding } from '@oslojs/encoding';

import type { AuthUser, IssuedSession, StoredSession } from '../../src';
import { generateToken } from '../../src/crypto/random';
import { timeStep, totpCode } from '../../src/plugins/two-factor/totp';
import { twoFactor, type SecretCipher, type TwoFactorOptions } from '../../src/plugins/two-factor';
import { MemoryTwoFactorStore } from '../../src/testing';
import { meta, PASSWORD, setup } from '../flows/setup';

export { meta, NEW_PASSWORD, PASSWORD, SECRET } from '../flows/setup';

export const EMAIL = 'ada@example.com';

type Session = StoredSession<Record<string, never>>;

/**
 * Not encryption: hex of the user id and the secret, enough to prove the plugin
 * stores what the cipher returns, hands the user id along, and decrypts before
 * it checks. Counts its calls for the timing tests.
 */
export function testCipher() {
  const calls = { encrypt: 0, decrypt: 0 };
  const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');

  const cipher: SecretCipher = {
    async encrypt(secret, { userId }) {
      calls.encrypt++;

      return `sealed:${Buffer.from(userId).toString('hex')}:${hex(secret)}`;
    },
    async decrypt(ciphertext, { userId }) {
      calls.decrypt++;

      const [tag, owner, body] = ciphertext.split(':');

      if (tag !== 'sealed' || owner !== Buffer.from(userId).toString('hex'))
        throw new Error('ciphertext does not belong to this user');

      return new Uint8Array(Buffer.from(body ?? '', 'hex'));
    },
  };

  return { cipher, calls };
}

type PluginOverrides = Partial<Omit<TwoFactorOptions, 'store' | 'cipher'>>;

/** An app with the two-factor plugin. */
export function twoFactorApp(
  plugin: PluginOverrides = {},
  overrides: Parameters<typeof setup>[0] = {},
) {
  const store = new MemoryTwoFactorStore();
  const { cipher, calls } = testCipher();
  const tf = twoFactor({ store, cipher, issuer: 'Acme', ...plugin });
  const env = setup({ ...overrides, plugins: [tf, ...(overrides.plugins ?? [])] });

  const auth = env.auth as typeof env.auth & {
    twoFactor: ReturnType<NonNullable<typeof tf.flows>>;
  };

  /** The code an authenticator app shows for `secret` now (plus `steps` steps). */
  const codeFor = (secret: string, steps = 0) =>
    totpCode(decodeBase32IgnorePadding(secret), timeStep(env.clock.now()) + steps);

  /** Moves to the start of the next time step, so a new code is due. */
  const nextStep = () => env.clock.advance(30_000);

  /** Registers and signs in (no factor yet). */
  async function signedIn(email = EMAIL, ip = '203.0.113.7') {
    const { token, session } = await env.signedInUser(email, ip);

    return { token, session: session as Session };
  }

  /** A signed-in user with a confirmed factor; the session holds a step-up from the confirmation. */
  async function enrolled(email = EMAIL) {
    const { session, token } = await signedIn(email);
    const started = await auth.twoFactor.enroll({ session, meta: meta() });

    if (!started.ok) throw new Error(`enroll failed: ${started.reason}`);

    const secret = started.value.secret;

    const confirmed = await auth.twoFactor.confirmEnrollment({
      session,
      code: codeFor(secret),
      meta: meta(),
    });

    if (!confirmed.ok) throw new Error(`confirm failed: ${confirmed.reason}`);

    nextStep();

    return {
      session,
      token,
      secret,
      recoveryCodes: confirmed.value.recoveryCodes,
      userId: session.userId,
    };
  }

  /** Logs in with the password and returns the challenge (throws when a session came back). */
  async function challenged(email = EMAIL, options: { ip?: string; userAgent?: string } = {}) {
    const login = await auth.login({
      email,
      password: PASSWORD,
      meta: { ...meta(options.ip), userAgent: options.userAgent ?? 'vitest' },
    });

    if (!login.ok || login.value.kind !== 'challenge')
      throw new Error(`expected a challenge: ${JSON.stringify(login)}`);

    return login.value;
  }

  /** Passes a fresh challenge with the current code and returns the session. */
  async function passed(secret: string, email = EMAIL) {
    const { challenge } = await challenged(email);

    const done = await auth.twoFactor.verifyChallenge({
      challenge,
      proof: { kind: 'totp', code: codeFor(secret) },
      meta: meta(),
    });

    if (!done.ok) throw new Error(`challenge failed: ${done.reason}`);

    nextStep();

    return done.value.session as IssuedSession<Record<string, never>>;
  }

  return {
    ...env,
    auth,
    store,
    cipher,
    cipherCalls: calls,
    codeFor,
    nextStep,
    signedIn,
    enrolled,
    challenged,
    passed,
  };
}

export type TwoFactorApp = ReturnType<typeof twoFactorApp>;

/** A token-shaped string nobody issued. */
export const unknownToken = () => generateToken();

/** A user handed to hooks in direct tests. */
export const someUser = (id = 'user-1'): AuthUser => ({ id, email: EMAIL, emailVerified: true });

const TWO_FACTOR_METHODS = [
  'findFactor',
  'putPendingFactor',
  'confirmFactor',
  'advanceStep',
  'deleteFactor',
  'replaceRecoveryCodes',
  'consumeRecoveryCode',
  'countRecoveryCodes',
  'addTrustedDevice',
  'findTrustedDevice',
  'deleteTrustedDevices',
  'putStepUp',
  'findStepUp',
] as const;

/** Records every two-factor store call as `twoFactor.method`, into `calls`. */
export function recordTwoFactorCalls(store: MemoryTwoFactorStore, calls: string[]): void {
  const target = store as unknown as Record<string, (...args: unknown[]) => unknown>;

  for (const method of TWO_FACTOR_METHODS) {
    const original = (target[method] as (...args: unknown[]) => unknown).bind(store);

    target[method] = (...args: unknown[]) => (calls.push(`twoFactor.${method}`), original(...args));
  }
}
