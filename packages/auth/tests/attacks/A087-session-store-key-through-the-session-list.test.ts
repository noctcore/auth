// A087: reading a session's store key through the session list, or using a
// handle to reach another user's session.
//
// A "where you're signed in" page shows the user's sessions. If the list
// carried each session's store key, anything that reads the page (an XSS
// payload, a browser extension, a shared screen, a client log) would learn
// the storage identity of every session of the account, and could match it
// offline against a leaked session store. The attacker then tries the other
// direction: feeding a raw store key, a handle from another account, or
// garbage to revoke, to sign someone out or to learn whether a handle exists.
//
// Stopped by: flows/session-management.ts (the list shows only the public
//   handle; revoke resolves a handle among the caller's own live sessions
//   only and answers the same for every handle it does not find; the
//   `sessionId` revoke answers for a session it ended is the store key, for
//   the server only, and auth-trpc's `revokedOutput` strips it),
//   core/auth-core.ts (`sessionHandle`: an HMAC of the store key under a key
//   derived from the server secret, so a handle cannot be computed from a
//   leaked store key without the secret), create-auth.ts (the handle key is
//   its own derived key).
// Learn: Sessions and expiry (/auth/learn/sessions-and-expiry/)
import { describe, expect, it } from 'vitest';

import { createAuth } from '../../src';
import { sha256Hex } from '../../src/crypto/hash';
import { plainHasher, recordingMailer } from '../../src/testing';
import { EMAIL, meta, PASSWORD, SECRET, setup } from './support';

async function twoAccounts() {
  const t = setup();
  const laptop = await t.signedInUser(EMAIL);

  const login = await t.auth.login({
    email: EMAIL,
    password: PASSWORD,
    meta: meta('198.51.100.2'),
  });

  if (!login.ok || login.value.kind !== 'session') throw new Error('phone login failed');

  const phone = { token: login.value.session.token, session: login.value.session.session };
  const eve = await t.signedInUser('eve@example.com', '192.0.2.99');

  return { ...t, laptop, phone, eve };
}

describe('A087: reading a session store key through the session list', () => {
  it('lists handles, never a store key or anything derived from it without the secret', async () => {
    const t = await twoAccounts();
    const list = await t.auth.sessions.list(t.laptop.session);
    const keys = [t.laptop.session.id, t.phone.session.id];
    const shown = JSON.stringify(list);

    expect(list).toHaveLength(2);

    for (const key of keys) {
      expect(shown).not.toContain(key);
      // A plain hash of the key is matchable offline against a leaked store.
      expect(shown).not.toContain(sha256Hex(key));
    }

    for (const entry of list) {
      expect(Object.keys(entry)).not.toContain('id');
      expect(entry.handle).toMatch(/^[\w-]{43}$/u);
    }
  });

  it('derives the same handle on every instance that shares the secret', async () => {
    const t = await twoAccounts();

    // A second server: its own createAuth over the same stores and secret.
    const peer = createAuth({
      stores: t.stores,
      password: { hasher: plainHasher(), breachCheck: false },
      secret: SECRET,
      urls: { resetPassword: (token) => `https://app.example/reset#${token}` },
      mailer: recordingMailer(),
      clock: t.clock,
    });

    expect(peer.sessions.handle(t.phone.session.id)).toBe(
      t.auth.sessions.handle(t.phone.session.id),
    );

    const fromOne = await t.auth.sessions.list(t.laptop.session);

    expect(await peer.sessions.list(t.laptop.session)).toEqual(fromOne);

    // A handle listed by one instance revokes through the other.
    const phone = fromOne.find((s) => !s.current);

    const revoked = await peer.sessions.revoke({
      session: t.laptop.session,
      handle: phone?.handle ?? '',
      meta: meta(),
    });

    expect(revoked).toEqual({ ok: true, value: { revoked: true, sessionId: t.phone.session.id } });
    expect(await t.sessionOf(t.phone.token)).toBeNull();
  });

  it('derives a different handle under a different secret', async () => {
    const t = await twoAccounts();

    const other = setup({ secret: 'another-secret-that-is-at-least-32-bytes' }).auth;

    expect(other.sessions.handle(t.phone.session.id)).not.toBe(
      t.auth.sessions.handle(t.phone.session.id),
    );
  });

  it('does not take a raw store key in place of a handle', async () => {
    const t = await twoAccounts();

    const result = await t.auth.sessions.revoke({
      session: t.laptop.session,
      handle: t.phone.session.id,
      meta: meta(),
    });

    expect(result).toEqual({ ok: true, value: { revoked: false } });
    expect(await t.sessionOf(t.phone.token)).not.toBeNull();
  });

  it("answers another user's handle exactly like garbage or a gone session", async () => {
    const t = await twoAccounts();
    const [victim] = await t.auth.sessions.list(t.phone.session);
    const victimHandle = victim?.handle ?? '';
    const gone = t.auth.sessions.handle('0'.repeat(64));

    const answers = [];

    for (const handle of [victimHandle, gone, 'not-a-handle', 'x'.repeat(128)])
      answers.push(await t.auth.sessions.revoke({ session: t.eve.session, handle, meta: meta() }));

    for (const answer of answers) expect(answer).toEqual({ ok: true, value: { revoked: false } });

    expect(await t.sessionOf(t.phone.token)).not.toBeNull();
    expect(await t.sessionOf(t.laptop.token)).not.toBeNull();
  });

  it('asks a stale session for fresh authentication before it looks a handle up', async () => {
    const t = await twoAccounts();
    const [victim] = await t.auth.sessions.list(t.phone.session);

    t.clock.advance(11 * 60_000);

    for (const handle of [victim?.handle ?? '', 'not-a-handle']) {
      const result = await t.auth.sessions.revoke({ session: t.eve.session, handle, meta: meta() });

      expect(!result.ok && result.code).toBe('fresh_auth_required');
    }
  });
});
