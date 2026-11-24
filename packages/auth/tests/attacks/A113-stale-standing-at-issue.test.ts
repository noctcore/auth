// A113: a session that skips enforcement on the strength of a standing
// stamped when it was issued, after the user came to need it.
//
// With `enforcementStanding: 'at-issue'`, a session issued unrestricted (a
// confirmed factor, or no factor required) carries a stamp and validates
// without reading the factor or the policy. If the stamp outlived a change,
// a user who must now enroll would keep a full session: an app that required
// a factor of them, an admin who reset their factor, a sign-in that read the
// policy just before a refresh, a session minted under another configuration
// or kept through a rollback to 'live', a re-issue that copied the stamp
// along, or a stamp an app hook or a legacy store supplied.
//
// Stopped by: plugins/two-factor/enforcement.ts (the stamp is a keyed hash of
//   the user, the version, the epoch read before the answer and the issue
//   time, verified on read and checked live after `maxAge`; `refreshStanding`
//   ends the user's sessions in either mode; `stampIsOurs` refuses a stamp
//   another hook supplied; the stamp is recomputed on every issue),
//   plugins/two-factor/management.ts (`reset` ends the sessions with
//   `enforcement`), session/session-manager.ts (the epoch fence on the mint).
// Learn: Second factors (/auth/learn/second-factors/)
import { describe, expect, it } from 'vitest';

import { definePlugin, type AuthUser, type PluginContext } from '../../src';
import { sha256Hex } from '../../src/crypto/hash';
import { generateToken } from '../../src/crypto/random';
import type { TwoFactorPolicy } from '../../src/plugins/two-factor';
import { EMAIL, meta, PASSWORD, standingApp as app, twoFactorApp } from '../two-factor/setup';

const MINUTE = 60_000;

describe('A113: changes that could restrict a stamped session end it', () => {
  it('ends the sessions when the app requires a factor and refreshes the standing', async () => {
    const t = app('at-issue');
    const { token, session } = await t.signedIn();

    t.policy.current = { required: true };

    expect(await t.auth.twoFactor.refreshStanding({ userId: session.userId })).toEqual({
      ok: true,
      value: { revoked: true },
    });

    expect((await t.validate(token)).ok).toBe(false);
    expect((await t.validate(await t.login())).standing).toEqual({ state: 'enrollment-only' });
  });

  it('gives the next sign-in the grace standing an admin set', async () => {
    const t = app('at-issue');
    const { token, session } = await t.signedIn();
    const graceEndsAt = t.clock.now() + 60 * MINUTE;

    t.policy.current = { required: true, graceEndsAt };
    await t.auth.twoFactor.refreshStanding({ userId: session.userId });

    expect((await t.validate(token)).ok).toBe(false);

    expect((await t.validate(await t.login())).standing).toEqual({ state: 'grace', graceEndsAt });
  });

  it('ends the sessions of a user whose factor an admin resets', async () => {
    const t = app('at-issue', { required: true });
    const { secret, userId } = await t.enrolled();
    const { token } = await t.passed(secret);

    await t.auth.twoFactor.reset({ userId, meta: meta() });

    expect((await t.validate(token)).ok).toBe(false);
    expect((await t.validate(await t.login())).standing).toEqual({ state: 'enrollment-only' });
  });

  it('restamps a re-issued session from the answer now, not the stamp it inherits', async () => {
    const t = app('at-issue');
    const { session } = await t.signedIn();

    // A change the app did not refresh; the password change re-issues the session.
    t.policy.current = { required: true };

    const changed = await t.auth.changePassword({
      session,
      currentPassword: PASSWORD,
      newPassword: 'another long passphrase',
      meta: meta(),
    });

    if (!changed.ok) throw new Error(changed.reason);

    expect((await t.validate(changed.value.token)).standing).toEqual({ state: 'enrollment-only' });
  });

  it("restamps an app's own re-issue at the same epoch from the answer now", async () => {
    let context: PluginContext<AuthUser, Record<string, never>> | undefined;

    const appSessions = definePlugin({
      id: 'appSessions',
      flows: (c) => {
        context = c as unknown as PluginContext<AuthUser, Record<string, never>>;

        return {};
      },
    });

    const t = app('at-issue', { required: false }, { plugins: [appSessions] });
    const { session } = await t.signedIn();
    const user = await t.stores.users.findById(session.userId);

    if (!user || !context) throw new Error('setup');

    // A change the app did not refresh; its own re-issue keeps the epoch.
    t.policy.current = { required: true };

    const reissued = await context.issueSession(user, {
      via: 'app-renew',
      meta: meta(),
      inherit: session,
    });

    if (!reissued.ok) throw new Error(reissued.reason);

    expect(reissued.value.session.epoch).toBe(session.epoch);
    expect((await t.validate(reissued.value.token)).standing).toEqual({ state: 'enrollment-only' });
  });

  it('leaves the sweep as the backstop for a policy changed without a refresh', async () => {
    const t = app('at-issue');
    const { token, session } = await t.signedIn();

    t.policy.current = { required: true };

    const swept = await t.auth.twoFactor.sweepUnenrolled({ userIds: [session.userId] });

    expect(swept.revoked).toEqual([session.userId]);
    expect((await t.validate(token)).ok).toBe(false);
  });

  it('does not stamp a session whose sign-in raced a refresh', async () => {
    let context: PluginContext<AuthUser, Record<string, never>> | undefined;

    const magicLink = definePlugin({
      id: 'magicLink',
      flows: (c) => {
        context = c as unknown as PluginContext<AuthUser, Record<string, never>>;

        return {};
      },
    });

    const policy = { current: { required: false } as TwoFactorPolicy, race: false };

    const t = twoFactorApp(
      {
        enforcementStanding: 'at-issue',
        enforcement: async ({ user }) => {
          const answer = policy.current;

          // The admin's change and refresh land after this answer was read.
          if (policy.race) {
            policy.race = false;
            policy.current = { required: true };
            await context?.revokeAllSessions(user.id, 'two-factor-standing');
          }

          return answer;
        },
      },
      { plugins: [magicLink] },
    );

    const { session } = await t.signedIn();
    const user = await t.stores.users.findById(session.userId);

    if (!user || !context) throw new Error('setup');

    policy.race = true;

    const issued = await context.issueSession(user, { via: 'magic-link', meta: meta() });

    if (!issued.ok) throw new Error(issued.reason);

    expect(await t.sessionOf(issued.value.token)).toMatchObject({
      twoFactor: { state: 'enrollment-only' },
    });
  });

  it('refuses a password login whose standing read raced a refresh', async () => {
    const admin: { refresh?: (userId: string) => Promise<unknown> } = {};
    let race = true;

    const t = twoFactorApp({
      enforcementStanding: 'at-issue',
      enforcement: async ({ user }) => {
        // The admin's refresh lands after the login read the epoch.
        if (race) {
          race = false;
          await admin.refresh?.(user.id);
        }

        return { required: false };
      },
    });

    admin.refresh = (userId) => t.auth.twoFactor.refreshStanding({ userId });

    await t.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });

    const login = await t.auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    expect(login).toMatchObject({ ok: false, code: 'session_expired', reason: 'epoch_fence' });
  });
});

describe('A113: sessions minted under another configuration are read live', () => {
  it('reads a session from before the option, or stamped under another version', async () => {
    const live = app(undefined);
    const { token } = await live.signedIn();
    // Later configurations of the same app: the same stores and clock. The
    // helper's types leave the stores to it, hence the casts.
    const sameStore = { store: live.store } as object;
    const sameEnv = { stores: live.stores, clock: live.clock } as object;

    // The same stores behind an app that now stamps: the old session has no stamp.
    const later = twoFactorApp(
      {
        ...sameStore,
        enforcement: () => ({ required: true }),
        enforcementStanding: 'at-issue',
      },
      sameEnv,
    );

    expect(await later.sessionOf(token)).toMatchObject({ twoFactor: { state: 'enrollment-only' } });

    const v1 = twoFactorApp(
      {
        ...sameStore,
        enforcement: () => ({ required: false }),
        enforcementStanding: { mode: 'at-issue', version: 'v1' },
      },
      sameEnv,
    );

    const stamped = await v1.auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    if (!stamped.ok || stamped.value.kind !== 'session') throw new Error('expected a session');

    // The policy changed for everyone and the version moved on: read live again.
    const v2 = twoFactorApp(
      {
        ...sameStore,
        enforcement: () => ({ required: true }),
        enforcementStanding: { mode: 'at-issue', version: 'v2' },
      },
      sameEnv,
    );

    expect(await v2.sessionOf(stamped.value.session.token)).toMatchObject({
      twoFactor: { state: 'enrollment-only' },
    });

    // And back to live: every session is read.
    const back = twoFactorApp({ ...sameStore, enforcement: () => ({ required: true }) }, sameEnv);

    expect(await back.sessionOf(stamped.value.session.token)).toMatchObject({
      twoFactor: { state: 'enrollment-only' },
    });
  });
});

describe('A113: a stamp from a spell under another mode', () => {
  it("does not come back after a rollback to 'live' and forward again", async () => {
    const first = app('at-issue');
    const { token, session } = await first.signedIn();
    const shared = { stores: first.stores, clock: first.clock } as object;

    expect((await first.validate(token)).reads.policy).toBe(0);

    // Rolled back to 'live': the admin requires a factor and refreshes.
    const rolledBack = twoFactorApp(
      { ...({ store: first.store } as object), enforcement: () => ({ required: true }) },
      shared,
    );

    expect(await rolledBack.auth.twoFactor.refreshStanding({ userId: session.userId })).toEqual({
      ok: true,
      value: { revoked: true },
    });

    // Forward to 'at-issue' again, same version: the old stamp is gone with its session.
    const forward = twoFactorApp(
      {
        ...({ store: first.store } as object),
        enforcement: () => ({ required: true }),
        enforcementStanding: 'at-issue',
      },
      shared,
    );

    expect(await forward.sessionOf(token)).toBeNull();
  });
});

describe('A113: a stamp the plugin did not make', () => {
  it('refuses a session whose stamp an app hook supplied, for a required user', async () => {
    const donor = app('at-issue');
    const { session: stamped } = await donor.signedIn('grace@example.com');
    const borrowed = (stamped.attributes as Record<string, unknown>)['twoFactorStanding'];

    expect(borrowed).toMatch(/^\d+\.[0-9a-f]{64}$/u);

    const t = app('at-issue', { required: true }, {
      hooks: { sessionAttributes: () => ({ twoFactorStanding: borrowed }) },
    } as never);

    await t.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });

    const login = await t.auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    expect(login).toMatchObject({ ok: false });
    expect(login.ok ? null : login.reason).toBe('two_factor_standing_replaced');
  });

  it('reads live a session whose stamp was copied from another user or epoch', async () => {
    const t = app('at-issue');
    const donor = await t.signedIn('grace@example.com');
    const stamp = (donor.session.attributes as Record<string, unknown>)['twoFactorStanding'];

    expect(stamp).toMatch(/^\d+\.[0-9a-f]{64}$/u);

    t.policy.current = { required: true };

    const victim = await t.signedIn();

    // The donor's sessions end: its epoch moves on.
    await t.auth.context.revokeAllSessions(donor.session.userId, 'admin');

    const donorEpoch = await t.auth.context.sessions.readEpoch(donor.session.userId);

    /** Stores a session record as a legacy store or a copy would hand it over. */
    async function planted(record: typeof victim.session) {
      const token = generateToken();

      await t.stores.sessions.create({ ...record, id: sha256Hex(token) }, 3600_000);

      return token;
    }

    // Another user's session with the donor's stamp.
    const otherUser = await planted({
      ...victim.session,
      attributes: { twoFactorStanding: stamp } as never,
    });

    // The donor's own session at its new epoch, with the stamp of the old one.
    const otherEpoch = await planted({ ...donor.session, epoch: donorEpoch });

    for (const token of [otherUser, otherEpoch])
      expect(await t.validate(token)).toMatchObject({
        ok: true,
        standing: { state: 'enrollment-only' },
      });
  });
});
