// A113: a session that skips enforcement on the strength of a standing
// stamped when it was issued, after the user came to need it.
//
// With `enforcementStanding: 'at-issue'`, a session issued unrestricted (a
// confirmed factor, or no factor required) carries a stamp and validates
// without reading the factor or the policy. If the stamp outlived a change,
// a user who must now enroll would keep a full session: an app that required
// a factor of them, an admin who reset their factor, a sign-in that read the
// policy just before a refresh, a session minted under another configuration,
// or a re-issue that copied the stamp along.
//
// Stopped by: plugins/two-factor/enforcement.ts (only a stamp of the current
//   version at the session's own epoch skips; the stamp carries the epoch read
//   before the answer; `refreshStanding` ends the user's sessions; the stamp is
//   recomputed on every issue), plugins/two-factor/management.ts (`reset` ends
//   the sessions under `'at-issue'`), session/session-manager.ts (the epoch
//   fence on the mint).
// Learn: Second factors (/auth/learn/second-factors/)
import { describe, expect, it } from 'vitest';

import { definePlugin, type AuthUser, type PluginContext } from '../../src';
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
