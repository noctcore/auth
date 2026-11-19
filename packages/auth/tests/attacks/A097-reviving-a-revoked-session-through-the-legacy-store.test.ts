// A097: bringing back a revoked session through the legacy store an app
// adopts sessions from.
//
// An app switching to the package's session store wraps it with
// `adoptLegacySessions` so its users stay signed in. The legacy records sit
// outside every revocation the package knows: a password change or a sign-out
// everywhere walks only the package's store. An attacker holding an old cookie
// (stolen before the switch, or kept from a shared machine) waits for the
// owner to change the password, then presents it; or replays a cookie after
// the owner signed out of the adopted session, hoping the legacy record is
// adopted a second time; or presents a legacy session whose own expiry lies
// years ahead, to outlive the store's revocation epoch.
//
// Stopped by: session/legacy-sessions.ts (`take` removes the legacy record
//   before the package session is written, so a record is adopted at most
//   once; the adopted session carries epoch 0, so any revocation of the user
//   since the switch refuses it; its expiry is capped at `maxTtl` after its
//   creation and never extended past the legacy expiry).
// Learn: Sessions and expiry (/auth/learn/sessions-and-expiry/)
import { describe, expect, it, vi } from 'vitest';

import { adoptLegacySessions, type LegacySession } from '../../src';
import { sha256Hex } from '../../src/crypto/hash';
import { generateToken } from '../../src/crypto/random';
import { EMAIL, meta, NEW_PASSWORD, PASSWORD, setup } from './support';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

/** An app on the package, adopting from its own session table (keyed by the token's SHA-256). */
function switchedApp() {
  const rows = new Map<string, LegacySession>();

  const take = vi.fn(async (id: string) => {
    const row = rows.get(id) ?? null;

    rows.delete(id);

    return row;
  });

  const base = setup();

  const sessions = adoptLegacySessions(base.stores.sessions, {
    take,
    maxTtl: '30d',
    clock: base.clock,
  });

  const app = setup({ stores: { ...base.stores, sessions }, clock: base.clock } as never);

  /** Puts a legacy session for `userId` in the app's old table and returns its cookie token. */
  function legacyCookie(userId: string, overrides: Partial<LegacySession> = {}) {
    const token = generateToken();
    const now = base.clock.now();

    rows.set(sha256Hex(token), {
      userId,
      createdAt: now - HOUR,
      authenticatedAt: now - HOUR,
      lastActiveAt: now - 60_000,
      expiresAt: now + 14 * DAY,
      idleTimeoutMs: 30 * DAY,
      rememberMe: true,
      ...overrides,
    });

    return token;
  }

  const validate = (token: string) => app.auth.validateRequest({ token, meta: meta() });

  return { ...app, clock: base.clock, rows, take, legacyCookie, validate };
}

describe('A097: bringing back a revoked session through the legacy store', () => {
  it('refuses a legacy cookie first presented after the owner changed the password', async () => {
    const t = switchedApp();
    const owner = await t.signedInUser(EMAIL);
    const stolen = t.legacyCookie(owner.session.userId);

    const changed = await t.auth.changePassword({
      session: owner.session,
      currentPassword: PASSWORD,
      newPassword: NEW_PASSWORD,
      meta: meta(),
    });

    expect(changed.ok).toBe(true);
    expect((await t.validate(stolen)).ok).toBe(false);
    // Taken and dropped: a later try finds nothing to adopt.
    expect(t.rows.size).toBe(0);
    expect((await t.validate(stolen)).ok).toBe(false);
  });

  it('refuses a legacy cookie first presented after a sign-out everywhere', async () => {
    const t = switchedApp();
    const owner = await t.signedInUser(EMAIL);
    const stolen = t.legacyCookie(owner.session.userId);

    await t.auth.sessions.revokeAll({ session: owner.session, meta: meta() });

    expect((await t.validate(stolen)).ok).toBe(false);
  });

  it('does not adopt a legacy session a second time after its owner signed out of it', async () => {
    const t = switchedApp();
    const owner = await t.signedInUser(EMAIL);
    const cookie = t.legacyCookie(owner.session.userId);

    expect((await t.validate(cookie)).ok).toBe(true);

    await t.auth.logout({ token: cookie, meta: meta() });

    expect((await t.validate(cookie)).ok).toBe(false);
    expect(t.take).toHaveBeenCalledTimes(2);
    expect(t.rows.size).toBe(0);
  });

  it('ends an adopted legacy session on a later password change, like any session', async () => {
    const t = switchedApp();
    const owner = await t.signedInUser(EMAIL);
    const cookie = t.legacyCookie(owner.session.userId);

    expect((await t.validate(cookie)).ok).toBe(true);

    await t.auth.changePassword({
      session: owner.session,
      currentPassword: PASSWORD,
      newPassword: NEW_PASSWORD,
      meta: meta(),
    });

    expect((await t.validate(cookie)).ok).toBe(false);
  });

  it('never lets a legacy session live past maxTtl from its creation, whatever its own expiry says', async () => {
    const t = switchedApp();
    const owner = await t.signedInUser(EMAIL);
    const now = t.clock.now();

    const old = t.legacyCookie(owner.session.userId, {
      createdAt: now - 31 * DAY,
      expiresAt: now + 365 * DAY,
    });

    expect((await t.validate(old)).ok).toBe(false);

    const recent = t.legacyCookie(owner.session.userId, {
      createdAt: now - 29 * DAY,
      expiresAt: now + 365 * DAY,
    });

    expect((await t.validate(recent)).ok).toBe(true);

    t.clock.advance(DAY);

    expect((await t.validate(recent)).ok).toBe(false);
  });
});
