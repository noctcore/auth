// A007: reusing a password reset token.
//
// A reset link or ticket is replayed after use, used after it expired, raced from
// two tabs, or a raw code is presented where only the ticket it buys is accepted.
// Or a reset link, code or ticket outlives a password write that failed or crashed
// halfway, and sets the password again later.
//
// Stopped by: tokens/one-time-tokens.ts (atomic single-use consume, expiry checked after the
//   consume, purpose-bound tokens), flows/password-reset.ts, flows/password-write.ts (every
//   reset purpose voided before the hash is written).
// Learn: Password reset (/auth/learn/password-reset/)
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { cryptoRandom } from '../../src/crypto/random';
import { manualClock, MemoryTokenStore, type ManualClock } from '../../src/testing';
import { OneTimeTokens } from '../../src/tokens/one-time-tokens';
import { codeFor, EMAIL, linkFor, meta, NEW_PASSWORD, PASSWORD, queued } from './support';

const secret = new TextEncoder().encode('server-secret-server-secret-0000');
let clock: ManualClock;
let store: MemoryTokenStore;
let tokens: OneTimeTokens;

beforeEach(() => {
  clock = manualClock();
  store = new MemoryTokenStore();
  tokens = new OneTimeTokens(store, clock, cryptoRandom, secret);
});

describe('A007: reusing a password reset token', () => {
  it('refuses an expired link and a replayed one', async () => {
    const t = queued();

    await t.signedInUser(EMAIL);
    const link = await linkFor(t);

    t.clock.advance(3_600_000);

    expect(
      (await t.auth.resetPassword({ token: link, password: NEW_PASSWORD, meta: meta() })).ok,
    ).toBe(false);

    const fresh = await linkFor(t);

    await t.auth.resetPassword({ token: fresh, password: NEW_PASSWORD, meta: meta() });

    const replay = await t.auth.resetPassword({
      token: fresh,
      password: NEW_PASSWORD,
      meta: meta(),
    });

    expect(!replay.ok && replay.code).toBe('invalid_token');
  });

  it('lets exactly one of two concurrent resets win', async () => {
    const t = queued();

    await t.signedInUser(EMAIL);
    const link = await linkFor(t);

    const results = await Promise.all([
      t.auth.resetPassword({ token: link, password: NEW_PASSWORD, meta: meta() }),
      t.auth.resetPassword({ token: link, password: 'yet another passphrase', meta: meta() }),
    ]);

    expect(results.filter((r) => r.ok)).toHaveLength(1);
  });

  it('refuses a raw code where a ticket is expected', async () => {
    const t = queued({ passwordReset: { kind: 'code' } });

    await t.signedInUser(EMAIL);
    const code = await codeFor(t);

    expect(
      (await t.auth.resetPassword({ token: code, password: NEW_PASSWORD, meta: meta() })).ok,
    ).toBe(false);
  });

  it('lets exactly one of many concurrent redemptions win', async () => {
    const { token } = await tokens.issueLink('verify', 'u1', 60_000);

    const results = await Promise.all(
      Array.from({ length: 20 }, () => tokens.redeemLink('verify', token)),
    );

    expect(results.filter((r) => r.status === 'valid')).toHaveLength(1);
  });
});

describe('A007: a reset token outliving a failed password write', () => {
  it('leaves no live reset code when the write after a ticket throws', async () => {
    const t = queued({ passwordReset: { kind: 'code' } });

    await t.signedInUser(EMAIL);

    const verified = await t.auth.verifyPasswordResetCode({
      email: EMAIL,
      code: await codeFor(t),
      meta: meta(),
    });

    if (!verified.ok) throw new Error('code refused');

    // A second reset asked for meanwhile: its code is waiting in the mailbox.
    const pending = await codeFor(t);

    vi.spyOn(t.stores.users, 'setPasswordHash').mockRejectedValueOnce(new Error('db down'));

    await expect(
      t.auth.resetPassword({ token: verified.value.ticket, password: NEW_PASSWORD, meta: meta() }),
    ).rejects.toThrow('db down');

    const later = await t.auth.verifyPasswordResetCode({
      email: EMAIL,
      code: pending,
      meta: meta(),
    });

    expect(!later.ok && later.code).toBe('invalid_token');
  });

  it('leaves no live reset link when a password change throws at the write', async () => {
    const t = queued();
    const { session } = await t.signedInUser(EMAIL);
    const link = await linkFor(t);

    vi.spyOn(t.stores.users, 'setPasswordHash').mockRejectedValueOnce(new Error('db down'));

    await expect(
      t.auth.changePassword({
        session,
        currentPassword: PASSWORD,
        newPassword: NEW_PASSWORD,
        meta: meta(),
      }),
    ).rejects.toThrow('db down');

    const reset = await t.auth.resetPassword({
      token: link,
      password: 'a passphrase from the link',
      meta: meta(),
    });

    expect(!reset.ok && reset.code).toBe('invalid_token');

    // The old password still signs in: the failed write changed nothing.
    const login = await t.auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

    expect(login.ok).toBe(true);
  });

  it('voids a link minted while the write ran', async () => {
    const t = queued();

    await t.signedInUser(EMAIL);
    const link = await linkFor(t);
    const write = t.stores.users.setPasswordHash.bind(t.stores.users);
    let minted = '';

    vi.spyOn(t.stores.users, 'setPasswordHash').mockImplementationOnce(async (...args) => {
      minted = await linkFor(t);

      return write(...args);
    });

    expect(
      (await t.auth.resetPassword({ token: link, password: NEW_PASSWORD, meta: meta() })).ok,
    ).toBe(true);

    const replay = await t.auth.resetPassword({
      token: minted,
      password: 'a passphrase from the link',
      meta: meta(),
    });

    expect(minted).not.toBe('');
    expect(!replay.ok && replay.code).toBe('invalid_token');
  });
});
