// Rotating the server secret with a grace window (`previousSecret`): values
// made under the old secret (codes, trusted-device cookies, session handles,
// keyed hashes) still verify, while everything new is signed and stored under
// the current secret only. Without `previousSecret` a rotation refuses them,
// as before.
import { describe, expect, it } from 'vitest';
import { AuthConfigError, createAuth, type RequestMeta } from '../../src';
import type { AuthCore } from '../../src/core/auth-core';
import { manualClock, memoryStores, plainHasher, recordingMailer } from '../../src/testing';

const OLD = 'the-old-server-secret-that-is-32-bytes-long';
const NEW = 'the-new-server-secret-that-is-32-bytes-long';
const OTHER = 'a-third-server-secret-that-is-32-bytes-long';
const EMAIL = 'ada@example.com';
const PASSWORD = 'correct horse battery';
const meta: RequestMeta = { ip: '203.0.113.7', userAgent: 'vitest' };

type Secret = string | Uint8Array;

/** One set of stores and one clock, and an app over them for any secret configuration. */
function world() {
  const clock = manualClock(Date.UTC(2026, 0, 1));
  const stores = memoryStores(clock);
  const mailer = recordingMailer();

  const app = (secret: Secret, previousSecret?: Secret | readonly Secret[]) =>
    createAuth({
      stores,
      password: { hasher: plainHasher(), breachCheck: false },
      secret,
      ...(previousSecret === undefined ? {} : { previousSecret }),
      passwordReset: { kind: 'code' },
      urls: {
        resetPassword: (token) => `https://app.example/reset#${token}`,
        verifyEmail: (token) => `https://app.example/verify#${token}`,
      },
      mailer,
      clock,
    });

  type App = ReturnType<typeof app>;

  async function signIn(auth: App) {
    const login = await auth.login({ email: EMAIL, password: PASSWORD, meta });

    if (!login.ok || login.value.kind !== 'session') throw new Error('login failed');

    return login.value.session;
  }

  async function resetCode(auth: App): Promise<string> {
    await auth.requestPasswordReset({ email: EMAIL, meta });
    await auth.flush();

    return mailer.last('password-reset-code')?.code ?? '';
  }

  async function deviceOk(auth: App, userId: string, token: string): Promise<boolean> {
    const epoch = await stores.sessions.getEpoch(userId);

    // The check login makes before it lets a correct password through a lock.
    const core = auth.context as unknown as Pick<AuthCore<never, never>, 'verifyDevice'>;

    return core.verifyDevice(userId, epoch, token) !== null;
  }

  async function register(auth: App) {
    const registered = await auth.register({ email: EMAIL, password: PASSWORD, meta });

    if (!registered.ok) throw new Error('register failed');

    await auth.flush();
  }

  return { clock, stores, mailer, app, signIn, resetCode, deviceOk, register };
}

describe('previousSecret', () => {
  it('keeps a code, a device cookie and a session handle from before the rotation working', async () => {
    const w = world();
    const before = w.app(OLD);

    await w.register(before);

    const issued = await w.signIn(before);
    const code = await w.resetCode(before);
    const [listed] = await before.sessions.list(issued.session);
    const rotated = w.app(NEW, OLD);

    expect(await w.deviceOk(rotated, issued.session.userId, issued.deviceCookie.value)).toBe(true);

    const ticket = await rotated.verifyPasswordResetCode({ email: EMAIL, code, meta });

    expect(ticket.ok).toBe(true);

    // The list shows the current handle; the one listed before still revokes.
    const [relisted] = await rotated.sessions.list(issued.session);

    expect(relisted?.handle).not.toBe(listed?.handle);

    const revoked = await rotated.sessions.revoke({
      session: issued.session,
      handle: listed?.handle ?? '',
      meta,
    });

    expect(revoked).toEqual({ ok: true, value: { revoked: true, sessionId: issued.session.id } });
  });

  it('refuses every old value after a rotation without it, as before', async () => {
    const w = world();
    const before = w.app(OLD);

    await w.register(before);

    const issued = await w.signIn(before);
    const code = await w.resetCode(before);
    const [listed] = await before.sessions.list(issued.session);
    const rotated = w.app(NEW);

    expect(await w.deviceOk(rotated, issued.session.userId, issued.deviceCookie.value)).toBe(false);
    expect((await rotated.verifyPasswordResetCode({ email: EMAIL, code, meta })).ok).toBe(false);

    // A handle from before names no session now.
    const revoked = await rotated.sessions.revoke({
      session: issued.session,
      handle: listed?.handle ?? '',
      meta,
    });

    expect(revoked).toEqual({ ok: true, value: { revoked: false } });
  });

  it('signs and stores everything new under the current secret only', async () => {
    const w = world();
    const rotated = w.app(NEW, OLD);

    await w.register(rotated);

    const issued = await w.signIn(rotated);
    const code = await w.resetCode(rotated);
    const [listed] = await rotated.sessions.list(issued.session);
    const oldOnly = w.app(OLD);
    const newOnly = w.app(NEW);
    const userId = issued.session.userId;

    // The device cookie.
    expect(await w.deviceOk(newOnly, userId, issued.deviceCookie.value)).toBe(true);
    expect(await w.deviceOk(oldOnly, userId, issued.deviceCookie.value)).toBe(false);

    // The keyed hashes a plugin stores, and the session handle a list shows.
    expect(rotated.context.keyedHash('p', 'm')).toBe(newOnly.context.keyedHash('p', 'm'));
    expect(rotated.context.keyedHash('p', 'm')).not.toBe(oldOnly.context.keyedHash('p', 'm'));

    expect(rotated.context.keyedHashes('p', 'm')).toEqual([
      newOnly.context.keyedHash('p', 'm'),
      oldOnly.context.keyedHash('p', 'm'),
    ]);

    expect(listed?.handle).toBe(newOnly.context.sessionHandle(issued.session.id));

    // The stored code hash: an app that only knows the old secret cannot match it.
    expect((await oldOnly.verifyPasswordResetCode({ email: EMAIL, code, meta })).ok).toBe(false);
    expect((await newOnly.verifyPasswordResetCode({ email: EMAIL, code, meta })).ok).toBe(true);

    // The next sign-in writes a new device cookie under the current secret.
    const again = await w.signIn(rotated);

    expect(await w.deviceOk(oldOnly, userId, again.deviceCookie.value)).toBe(false);
  });

  it('finds a code issued under the previous secret and counts one attempt per try', async () => {
    const w = world();
    const before = w.app(OLD);

    await w.register(before);

    const code = await w.resetCode(before);
    const rotated = w.app(NEW, [OTHER, OLD]);
    const wrong = code === '00000000' ? '11111111' : '00000000';
    const user = await w.stores.users.findCredentialByEmail(EMAIL as never);
    const stored = () => w.stores.tokens.findByUser('password-reset', user?.id ?? '');

    expect((await rotated.verifyPasswordResetCode({ email: EMAIL, code: wrong, meta })).ok).toBe(
      false,
    );

    expect((await stored())?.attempts).toBe(1);
    expect((await rotated.verifyPasswordResetCode({ email: EMAIL, code, meta })).ok).toBe(true);
  });

  it('takes the previous secrets as bytes or strings, one or a list', () => {
    const w = world();
    const bytes = new TextEncoder().encode(OLD);

    expect(w.app(NEW, bytes).context.keyedHashes('p', 'm')).toHaveLength(2);
    expect(w.app(NEW, [OTHER, bytes]).context.keyedHashes('p', 'm')).toHaveLength(3);
    expect(w.app(NEW, []).context.keyedHashes('p', 'm')).toHaveLength(1);
    expect(w.app(NEW).context.keyedHashes('p', 'm')).toHaveLength(1);
  });

  it('refuses a previous secret that equals the secret, repeats, is short or is not a secret', () => {
    const w = world();

    const cases: [unknown, RegExp][] = [
      [NEW, /differ/u],
      [new TextEncoder().encode(NEW), /differ/u],
      [[OLD, OLD], /differ/u],
      [[OLD, NEW], /differ/u],
      ['too-short', /at least 32 bytes/u],
      [[OLD, 'too-short'], /at least 32 bytes/u],
      [[OLD, 42], /string, bytes or a list/u],
      [{}, /string, bytes or a list/u],
    ];

    for (const [previous, message] of cases) {
      expect(() => w.app(NEW, previous as Secret), String(previous)).toThrow(AuthConfigError);
      expect(() => w.app(NEW, previous as Secret), String(previous)).toThrow(message);
    }
  });
});
