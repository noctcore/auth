import { describe, expect, it } from 'vitest';
import { AuthConfigError, createAuth, definePlugin, fail, ok, refuse, type AuthResult, type IssuedSession } from '../../src';
import type { AuthUser } from '../../src/stores';
import { manualClock, memoryStores, plainHasher, recordingMailer } from '../../src/testing';
import { meta, PASSWORD, SECRET, setup } from './setup';

/** A toy second factor: shows a plugin finishing a login through the issueSession seam. */
function toyTwoFactor() {
  const pending = new Map<string, { user: AuthUser; epoch: number; rememberMe: boolean }>();
  return definePlugin({
    id: 'twoFactor',
    hooks: {
      loginChallenge: ({ user, epoch, rememberMe }) => {
        const challenge = `challenge-${pending.size + 1}`;
        pending.set(challenge, { user, epoch, rememberMe });
        return { challenge, methods: ['toy'] };
      },
    },
    flows: (context) => ({
      async verify(input: { challenge: string; code: string }): Promise<AuthResult<IssuedSession<unknown>>> {
        // Consume the pending challenge BEFORE checking the code, so a lost race never burns a code.
        const entry = pending.get(input.challenge);
        pending.delete(input.challenge);
        if (!entry) return fail('invalid_second_factor', 'unknown_challenge');
        if (input.code !== '424242') return fail('invalid_second_factor', 'wrong_code');
        return context.issueSession(entry.user, { via: 'second-factor', meta: meta(), epoch: entry.epoch, rememberMe: entry.rememberMe });
      },
      ping: () => ok('pong'),
    }),
  });
}

/** `setup()` erases plugin types; `createAuth` called directly keeps them (see the second test). */
type WithToy = { twoFactor: ReturnType<NonNullable<ReturnType<typeof toyTwoFactor>['flows']>> };

describe('plugins', () => {
  it('namespaces plugin flows under the plugin id', () => {
    const { auth } = setup({ plugins: [toyTwoFactor()] });
    expect((auth as unknown as WithToy).twoFactor.ping()).toEqual({ ok: true, value: 'pong' });
  });

  it('finishes a challenged login through issueSession, which runs the app hooks', async () => {
    const created: string[] = [];
    const clock = manualClock();
    const auth = createAuth({
      stores: memoryStores(clock),
      password: { hasher: plainHasher() },
      secret: SECRET,
      urls: { resetPassword: (t) => t },
      mailer: recordingMailer(),
      clock,
      plugins: [toyTwoFactor()],
      hooks: { beforeSessionCreate: ({ via }) => void created.push(via) },
    });
    await auth.register({ email: 'ada@example.com', password: PASSWORD, meta: meta() });
    const login = await auth.login({ email: 'ada@example.com', password: PASSWORD, meta: meta() });
    if (!login.ok || login.value.kind !== 'challenge') throw new Error('expected a challenge');

    const wrong = await auth.twoFactor.verify({ challenge: login.value.challenge, code: '000000' });
    expect(!wrong.ok && wrong.code).toBe('invalid_second_factor');
    const login2 = await auth.login({ email: 'ada@example.com', password: PASSWORD, meta: meta() });
    if (!login2.ok || login2.value.kind !== 'challenge') throw new Error('expected a challenge');
    const done = await auth.twoFactor.verify({ challenge: login2.value.challenge, code: '424242' });
    expect(done.ok).toBe(true);
    expect(created).toEqual(['second-factor']);
  });

  it('refuses the second-factor session when the password changed during the challenge (epoch carried along)', async () => {
    const { auth, stores } = setup({ plugins: [toyTwoFactor()] });
    await auth.register({ email: 'ada@example.com', password: PASSWORD, meta: meta() });
    const login = await auth.login({ email: 'ada@example.com', password: PASSWORD, meta: meta() });
    if (!login.ok || login.value.kind !== 'challenge') throw new Error('expected a challenge');
    const user = await stores.users.findCredentialByEmail('ada@example.com' as never);
    await auth.context.revokeAllSessions(user?.id ?? '', 'password-change');
    const done = await (auth as unknown as WithToy).twoFactor.verify({ challenge: login.value.challenge, code: '424242' });
    expect(!done.ok && done.reason).toBe('epoch_fence');
  });

  it('runs plugin hooks before app hooks, and any refusal wins', async () => {
    const order: string[] = [];
    const plugin = definePlugin({ id: 'first', hooks: { beforeSessionCreate: () => void order.push('plugin') } });
    const { auth } = setup({
      plugins: [plugin],
      hooks: { beforeSessionCreate: () => (order.push('app'), refuse('app_says_no')) },
    });
    await auth.register({ email: 'ada@example.com', password: PASSWORD, meta: meta() });
    const login = await auth.login({ email: 'ada@example.com', password: PASSWORD, meta: meta() });
    expect(order).toEqual(['plugin', 'app']);
    expect(!login.ok && login.reason).toBe('app_says_no');
  });

  it('refuses duplicate ids, ids that collide with core flows and unmet requirements', () => {
    expect(() => setup({ plugins: [definePlugin({ id: 'x' }), definePlugin({ id: 'x' })] })).toThrow(AuthConfigError);
    expect(() => setup({ plugins: [definePlugin({ id: 'login', flows: () => ({}) })] })).toThrow(AuthConfigError);
    expect(() => setup({ plugins: [definePlugin({ id: 'needsCaptcha', requires: ['captcha'] })] })).toThrow(AuthConfigError);
  });
});

describe('createAuth configuration', () => {
  const base = () => ({ stores: memoryStores(), password: { hasher: plainHasher() }, mailer: recordingMailer() });

  it('requires a secret of 32 bytes or more when codes are in use (the default)', () => {
    expect(() => createAuth({ ...base(), urls: { resetPassword: (t) => t } })).toThrow(/secret is required/u);
    expect(() => createAuth({ ...base(), secret: 'short', urls: { resetPassword: (t) => t } })).toThrow(/at least 32 bytes/u);
  });

  it('requires the URL builders for link flows', () => {
    expect(() => createAuth({ ...base(), secret: SECRET })).toThrow(/urls.resetPassword/u);
    expect(() => createAuth({ ...base(), emailVerification: { kind: 'link' }, passwordReset: { kind: 'code' }, secret: SECRET })).toThrow(
      /urls.verifyEmail/u,
    );
  });

  it('refuses a password minimum below 8 and code lengths outside 6 to 9', () => {
    const ok = { ...base(), secret: SECRET, urls: { resetPassword: (t: string) => t } };
    expect(() => createAuth({ ...ok, password: { hasher: plainHasher(), policy: { minLength: 6 } } })).toThrow(AuthConfigError);
    expect(() => createAuth({ ...ok, emailVerification: { digits: 12 } })).toThrow(AuthConfigError);
  });
});
