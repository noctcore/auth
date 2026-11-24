import { describe, expect, it } from 'vitest';

import {
  AuthConfigError,
  definePlugin,
  type AuthUser,
  type PluginContext,
  type StoredSession,
} from '../../src';
import { twoFactor } from '../../src/plugins/two-factor';
import { MemoryTwoFactorStore } from '../../src/testing';
import { meta, testCipher, twoFactorApp } from './setup';

type Session = StoredSession<Record<string, never>>;

const MINUTE = 60_000;

/** Sessions that stay live and fresh across the long windows these tests wait out. */
const longSessions = { session: { freshAuthAge: '3h', idleTimeout: '3h' } } as never;

async function started(t: ReturnType<typeof twoFactorApp>) {
  const { session } = await t.signedIn();
  const enrollment = await t.auth.twoFactor.enroll({ session, meta: meta() });

  if (!enrollment.ok) throw new Error(enrollment.reason);

  return { session, enrollment: enrollment.value };
}

describe('enrollmentWindow', () => {
  it('keeps a pending secret for the configured window', async () => {
    const t = twoFactorApp({ enrollmentWindow: '1h' }, longSessions);
    const { session, enrollment } = await started(t);

    expect(enrollment.expiresAt).toBe(t.clock.now() + 60 * MINUTE);

    t.clock.advance(50 * MINUTE);

    const confirmed = await t.auth.twoFactor.confirmEnrollment({
      session,
      code: t.codeFor(enrollment.secret),
      meta: meta(),
    });

    expect(confirmed.ok).toBe(true);
  });

  it('refuses the code once the configured window is over', async () => {
    const t = twoFactorApp({ enrollmentWindow: '1h' }, longSessions);
    const { session, enrollment } = await started(t);

    t.clock.advance(61 * MINUTE);

    const late = await t.auth.twoFactor.confirmEnrollment({
      session,
      code: t.codeFor(enrollment.secret),
      meta: meta(),
    });

    expect(late).toMatchObject({ ok: false, reason: 'no_pending_enrollment' });
  });

  it('keeps 10 minutes by default', async () => {
    const t = twoFactorApp({}, longSessions);
    const { session, enrollment } = await started(t);

    expect(enrollment.expiresAt).toBe(t.clock.now() + 10 * MINUTE);

    t.clock.advance(10 * MINUTE);

    const late = await t.auth.twoFactor.confirmEnrollment({
      session,
      code: t.codeFor(enrollment.secret),
      meta: meta(),
    });

    expect(late).toMatchObject({ ok: false, reason: 'no_pending_enrollment' });
  });

  it.each([0, -1, '0s', '25h', 'soon', 24 * 3600 + 1])('refuses %s', (enrollmentWindow) => {
    const { cipher } = testCipher();

    expect(() =>
      twoFactor({
        store: new MemoryTwoFactorStore(),
        cipher,
        issuer: 'Acme',
        enrollmentWindow: enrollmentWindow as never,
      }),
    ).toThrow(AuthConfigError);
  });

  it('accepts 24 hours', () => {
    const { cipher } = testCipher();

    expect(() =>
      twoFactor({
        store: new MemoryTwoFactorStore(),
        cipher,
        issuer: 'Acme',
        enrollmentWindow: '24h',
      }),
    ).not.toThrow();
  });

  it("dates an app's re-issue check from the configured window", async () => {
    let context: PluginContext<AuthUser, Record<string, never>> | undefined;

    const app = definePlugin({
      id: 'appSessions',
      flows: (c) => {
        context = c as unknown as PluginContext<AuthUser, Record<string, never>>;

        return {};
      },
    });

    const t = twoFactorApp(
      { enrollmentWindow: '1h' },
      { ...(longSessions as object), plugins: [app] },
    );

    const { secret, userId } = await t.enrolled();
    const user = await t.stores.users.findById(userId);

    if (!user || !context) throw new Error('setup');

    const reissue = (inherit: Session) =>
      context?.issueSession(user, { via: 'app-password-change', meta: meta(), inherit });

    // Created 30 minutes in: inside the 1 hour window, and its step-up lapsed.
    t.clock.advance(30 * MINUTE);

    const inside = (await t.passed(secret)).session as Session;

    t.clock.advance(11 * MINUTE);

    expect(await reissue(inside)).toMatchObject({ ok: false, code: 'second_factor_required' });

    // Created after the window closed: it passes.
    t.clock.advance(20 * MINUTE);

    const after = (await t.passed(secret)).session as Session;

    t.clock.advance(11 * MINUTE);

    expect((await reissue(after))?.ok).toBe(true);
  });
});
