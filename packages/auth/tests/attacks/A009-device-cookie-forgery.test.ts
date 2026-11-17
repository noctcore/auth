// A009: forging or hoarding trusted-device cookies.
//
// An attacker forges, edits or truncates a device cookie, presents their own
// account's cookie against the victim, or collects many cookies, to get past a
// lock or to get more guesses.
//
// Stopped by: throttle/device-token.ts (HMAC over user, epoch and issue time; canonical
//   spelling), throttle/throttle.ts (per-device and shared device budgets),
//   session/session-manager.ts (the epoch bump voids old cookies).
//   Property tests: tests/property/device-token.property.test.ts.
// Learn: Brute force and lockout (/auth/learn/brute-force-and-lockout/)
import { describe, expect, it } from 'vitest';

import { EMAIL, meta, NEW_PASSWORD, PASSWORD, registered, setup } from './support';

describe('A009: forging or hoarding trusted-device cookies', () => {
  it('probe I: old device tokens are void after a reset, and many tokens add no guesses', async () => {
    const env = setup({ passwordReset: { kind: 'code' } });

    await env.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });

    const mint = async (i: number) => {
      const r = await env.auth.login({
        email: EMAIL,
        password: PASSWORD,
        meta: meta(`203.0.113.${i}`),
      });

      if (!r.ok || r.value.kind !== 'session') throw new Error('login failed');

      return r.value.session.deviceCookie.value;
    };

    const old: string[] = [];

    for (let i = 0; i < 10; i++) old.push(await mint(i));

    // A password reset bumps the epoch.
    await env.auth.requestPasswordReset({ email: EMAIL, meta: meta() });
    await new Promise((resolve) => setTimeout(resolve, 20));
    const code = env.mailer.last('password-reset-code')?.code ?? '';
    const ticket = await env.auth.verifyPasswordResetCode({ email: EMAIL, code, meta: meta() });

    if (!ticket.ok) throw new Error(ticket.reason);

    expect(
      (
        await env.auth.resetPassword({
          token: ticket.value.ticket,
          password: NEW_PASSWORD,
          meta: meta(),
        })
      ).ok,
    ).toBe(true);

    // The account gets locked by a distributed attack.
    for (let i = 0; i < 11; i++)
      await env.auth.login({
        email: EMAIL,
        password: 'wrong passphrase!',
        meta: meta(`192.0.2.${i}`),
      });

    // Old tokens: even the right new password is refused while locked.
    for (const [i, deviceToken] of old.entries()) {
      const r = await env.auth.login({
        email: EMAIL,
        password: NEW_PASSWORD,
        deviceToken,
        meta: meta(`203.0.113.${i}`),
      });

      expect(!r.ok && r.reason).toBe('locked');
    }

    // Ten fresh, valid tokens (minted after the lock expires) give five guesses in all, not fifty.
    env.clock.advance(60 * 60_000);
    const fresh: string[] = [];

    for (let i = 0; i < 10; i++) {
      const r = await env.auth.login({
        email: EMAIL,
        password: NEW_PASSWORD,
        meta: meta(`198.18.0.${i}`),
      });

      if (!r.ok || r.value.kind !== 'session') throw new Error(`fresh login ${i} failed`);

      fresh.push(r.value.session.deviceCookie.value);
    }

    for (let i = 0; i < 11; i++)
      await env.auth.login({
        email: EMAIL,
        password: 'wrong passphrase!',
        meta: meta(`198.51.100.${i}`),
      });

    let letThrough = 0;

    for (let i = 0; i < 50; i++) {
      const deviceToken = fresh[i % fresh.length] ?? null;

      const r = await env.auth.login({
        email: EMAIL,
        password: 'guess number ' + String(i).padStart(4, '0'),
        deviceToken,
        meta: meta(`203.0.113.${i}`),
      });

      if (!r.ok && r.reason === 'wrong_password') letThrough++;
    }

    expect(letThrough).toBe(5);

    // Even the right password is now refused on every token until the window ends.
    const owner = await env.auth.login({
      email: EMAIL,
      password: NEW_PASSWORD,
      deviceToken: fresh[0] ?? null,
      meta: meta('198.18.1.1'),
    });

    expect(!owner.ok && owner.reason).toBe('device_budget');
  });

  async function lockedOwnerWithCookie() {
    const env = await registered();

    const first = await env.auth.login({
      email: EMAIL,
      password: PASSWORD,
      meta: meta('203.0.113.5'),
    });

    if (!first.ok || first.value.kind !== 'session') throw new Error('first login failed');

    for (let i = 0; i < 11; i++)
      await env.auth.login({
        email: EMAIL,
        password: 'wrong passphrase!',
        meta: meta(`192.0.2.${i}`),
      });

    return { ...env, cookie: first.value.session.deviceCookie.value };
  }

  it("does not let the attacker's own device cookie through the victim's lock", async () => {
    const env = await lockedOwnerWithCookie();

    await env.auth.register({
      email: 'eve@example.com',
      password: PASSWORD,
      meta: meta('198.51.100.9'),
    });

    const eve = await env.auth.login({
      email: 'eve@example.com',
      password: PASSWORD,
      meta: meta('198.51.100.9'),
    });

    if (!eve.ok || eve.value.kind !== 'session') throw new Error('eve login failed');

    const attempt = await env.auth.login({
      email: EMAIL,
      password: PASSWORD,
      deviceToken: eve.value.session.deviceCookie.value,
      meta: meta('198.51.100.9'),
    });

    expect(!attempt.ok && attempt.reason).toBe('locked');
  });

  it('refuses an edited, truncated, zero-padded or re-signed cookie under a lock', async () => {
    const env = await lockedOwnerWithCookie();
    const [id = '', issued = '', epoch = '', mac = ''] = env.cookie.split('.');
    const flip = (s: string) => (s.startsWith('0') ? `1${s.slice(1)}` : `0${s.slice(1)}`);

    const forged = [
      `${id}.${issued}.${epoch}.${flip(mac)}`,
      `${flip(id)}.${issued}.${epoch}.${mac}`,
      `${id}.${Number(issued) + 1}.${epoch}.${mac}`,
      `${id}.0${issued}.${epoch}.${mac}`,
      `${id}.${issued}.0${epoch}.${mac}`,
      `${id}.${issued}.${epoch}.${mac.slice(0, -1)}`,
      env.cookie.slice(0, 40),
      `${id}.${issued}.${epoch}.${'0'.repeat(64)}`,
      '',
    ];

    for (const [i, deviceToken] of forged.entries()) {
      const attempt = await env.auth.login({
        email: EMAIL,
        password: PASSWORD,
        deviceToken,
        meta: meta(`203.0.113.${100 + i}`),
      });

      expect(!attempt.ok && attempt.reason).toBe('locked');
    }

    const genuine = await env.auth.login({
      email: EMAIL,
      password: PASSWORD,
      deviceToken: env.cookie,
      meta: meta('203.0.113.5'),
    });

    expect(genuine.ok).toBe(true);
  });

  it('refuses a cookie older than its maximum age, whatever the browser kept', async () => {
    const env = await lockedOwnerWithCookie();

    env.clock.advance(31 * 24 * 60 * 60_000);

    // A new lock, so the cookie matters again.
    for (let i = 0; i < 11; i++)
      await env.auth.login({
        email: EMAIL,
        password: 'wrong passphrase!',
        meta: meta(`192.0.3.${i}`),
      });

    const stale = await env.auth.login({
      email: EMAIL,
      password: PASSWORD,
      deviceToken: env.cookie,
      meta: meta('203.0.113.5'),
    });

    expect(!stale.ok && stale.reason).toBe('locked');
    expect(setup).toBeTypeOf('function');
  });
});
