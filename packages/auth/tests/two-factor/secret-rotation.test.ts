// Recovery codes across a server secret rotation: they are stored as keyed
// hashes under the secret, so a code from before the rotation is spent under
// `previousSecret` while it is configured, and a set made after it is stored
// under the current secret only.
import { describe, expect, it } from 'vitest';
import { createAuth, type AuthPlugin, type StoredSession } from '../../src';
import { twoFactor } from '../../src/plugins/two-factor';
import { plainHasher } from '../../src/testing';
import { EMAIL, meta, PASSWORD, SECRET, twoFactorApp } from './setup';

const NEW = 'the-new-server-secret-that-is-32-bytes-long';

/** The same stores, factor store and cipher as `t`, under another secret configuration. */
function restarted(t: ReturnType<typeof twoFactorApp>, secret: string, previousSecret?: string) {
  const plugin = twoFactor({ store: t.store, cipher: t.cipher, issuer: 'Acme' });

  const auth = createAuth({
    stores: t.stores,
    password: { hasher: plainHasher(), breachCheck: false },
    secret,
    ...(previousSecret === undefined ? {} : { previousSecret }),
    urls: {
      resetPassword: (token) => `https://app.example/reset#${token}`,
      verifyEmail: (token) => `https://app.example/verify#${token}`,
    },
    mailer: t.mailer,
    clock: t.clock,
    plugins: [plugin as AuthPlugin],
  });

  return auth as typeof auth & { twoFactor: ReturnType<NonNullable<typeof plugin.flows>> };
}

async function recoveryLogin(auth: ReturnType<typeof restarted>, code: string) {
  const login = await auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

  if (!login.ok || login.value.kind !== 'challenge') throw new Error('expected a challenge');

  return auth.twoFactor.verifyChallenge({
    challenge: login.value.challenge,
    proof: { kind: 'recovery-code', code },
    meta: meta(),
  });
}

describe('recovery codes across a secret rotation', () => {
  it('spends a code from before the rotation while previousSecret is set, and refuses it without', async () => {
    const t = twoFactorApp();
    const { recoveryCodes, userId } = await t.enrolled();

    expect((await recoveryLogin(restarted(t, NEW), recoveryCodes[0] ?? '')).ok).toBe(false);

    const rotated = restarted(t, NEW, SECRET);

    expect((await recoveryLogin(rotated, recoveryCodes[0] ?? '')).ok).toBe(true);
    expect(await t.store.countRecoveryCodes(userId)).toBe(9);

    // Spent once, under whichever key matched.
    expect((await recoveryLogin(rotated, recoveryCodes[0] ?? '')).ok).toBe(false);
  });

  it('stores a set made after the rotation under the current secret only', async () => {
    const t = twoFactorApp();
    const { recoveryCodes } = await t.enrolled();
    const rotated = restarted(t, NEW, SECRET);
    const login = await recoveryLogin(rotated, recoveryCodes[0] ?? '');

    if (!login.ok) throw new Error('recovery login failed');

    const session = login.value.session.session as StoredSession<Record<string, never>>;
    const fresh = await rotated.twoFactor.regenerateRecoveryCodes({ session, meta: meta() });

    if (!fresh.ok) throw new Error(`regenerate failed: ${fresh.reason}`);

    const [first = '', second = ''] = fresh.value.recoveryCodes;

    expect((await recoveryLogin(restarted(t, SECRET), first)).ok).toBe(false);
    expect((await recoveryLogin(restarted(t, NEW), second)).ok).toBe(true);
  });
});
