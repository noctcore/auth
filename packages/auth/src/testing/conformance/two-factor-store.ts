/**
 * TwoFactorStore conformance: the properties the two-factor plugin relies on.
 * A time step moves only forward and only once (TOTP replay), enrollment
 * confirms only the secret it was checked against, a recovery code is spent
 * once under concurrency, and replacing the set voids every old code.
 *
 * Guide: Build, "Writing a store adapter".
 */
import assert from 'node:assert/strict';
import { systemClock } from '../../ports/clock';
import type { StoredTrustedDevice, TwoFactorStore } from '../../ports/two-factor';
import { times, uniqueId, type ConformanceCase } from '../harness';

function device(userId: string, overrides: Partial<StoredTrustedDevice> = {}): StoredTrustedDevice {
  const now = systemClock.now();

  return {
    userId,
    hash: uniqueId('device'),
    epoch: 0,
    createdAt: now,
    expiresAt: now + 60_000,
    ...overrides,
  };
}

async function confirmedFactor(store: TwoFactorStore, step = 100): Promise<string> {
  const userId = uniqueId('user');

  await store.putPendingFactor({ userId, secret: 'ciphertext', createdAt: systemClock.now() });
  assert.equal(await store.confirmFactor(userId, 'ciphertext', step), true);

  return userId;
}

export function twoFactorStoreConformance(store: TwoFactorStore): ConformanceCase[] {
  return [
    {
      name: 'stores a pending factor and replaces a pending one',
      async run() {
        const userId = uniqueId('user');
        const createdAt = systemClock.now();

        assert.equal(await store.findFactor(userId), null);
        assert.equal(await store.putPendingFactor({ userId, secret: 'first', createdAt }), true);
        assert.equal(await store.putPendingFactor({ userId, secret: 'second', createdAt }), true);

        assert.deepEqual(await store.findFactor(userId), {
          userId,
          secret: 'second',
          confirmed: false,
          lastStep: -1,
          createdAt,
        });
      },
    },
    {
      name: 'confirms a factor only against the secret it still holds, once',
      async run() {
        const userId = uniqueId('user');
        const createdAt = systemClock.now();

        await store.putPendingFactor({ userId, secret: 'first', createdAt });
        await store.putPendingFactor({ userId, secret: 'second', createdAt });
        assert.equal(await store.confirmFactor(userId, 'first', 10), false);
        assert.equal(await store.confirmFactor(uniqueId('nobody'), 'second', 10), false);
        assert.equal(await store.confirmFactor(userId, 'second', 10), true);
        assert.equal(await store.confirmFactor(userId, 'second', 11), false);

        assert.deepEqual(await store.findFactor(userId), {
          userId,
          secret: 'second',
          confirmed: true,
          lastStep: 10,
          createdAt,
        });
      },
    },
    {
      name: 'never replaces a confirmed factor with a pending one',
      async run() {
        const userId = await confirmedFactor(store);

        assert.equal(
          await store.putPendingFactor({ userId, secret: 'other', createdAt: systemClock.now() }),
          false,
        );

        assert.equal((await store.findFactor(userId))?.secret, 'ciphertext');
        assert.equal((await store.findFactor(userId))?.confirmed, true);
      },
    },
    {
      name: 'concurrent confirmations of one pending factor: exactly one wins',
      async run() {
        const userId = uniqueId('user');

        await store.putPendingFactor({ userId, secret: 'secret', createdAt: systemClock.now() });
        const results = await times(20, (i) => store.confirmFactor(userId, 'secret', 50 + i));

        assert.equal(results.filter(Boolean).length, 1);
      },
    },
    {
      name: 'moves the last step only forward, and never on a pending or missing factor',
      async run() {
        const userId = await confirmedFactor(store, 100);

        assert.equal(await store.advanceStep(userId, 100), false);
        assert.equal(await store.advanceStep(userId, 99), false);
        assert.equal(await store.advanceStep(userId, 101), true);
        assert.equal(await store.advanceStep(userId, 101), false);
        assert.equal(await store.advanceStep(userId, 103), true);
        assert.equal((await store.findFactor(userId))?.lastStep, 103);

        const pending = uniqueId('user');

        await store.putPendingFactor({
          userId: pending,
          secret: 's',
          createdAt: systemClock.now(),
        });

        assert.equal(await store.advanceStep(pending, 5), false);
        assert.equal(await store.advanceStep(uniqueId('nobody'), 5), false);
      },
    },
    {
      name: 'advanceStep under 50 concurrent callers with the same step: exactly one wins',
      async run() {
        const userId = await confirmedFactor(store, 100);
        const results = await times(50, () => store.advanceStep(userId, 101));

        assert.equal(results.filter(Boolean).length, 1);
        assert.equal((await store.findFactor(userId))?.lastStep, 101);
      },
    },
    {
      name: 'deletes a factor',
      async run() {
        const userId = await confirmedFactor(store);

        await store.deleteFactor(userId);
        assert.equal(await store.findFactor(userId), null);
        await store.deleteFactor(userId);
      },
    },
    {
      name: 'stores recovery codes, counts them and consumes each once',
      async run() {
        const userId = uniqueId('user');

        assert.equal(await store.countRecoveryCodes(userId), 0);
        await store.replaceRecoveryCodes(userId, ['a', 'b', 'c']);
        assert.equal(await store.countRecoveryCodes(userId), 3);
        assert.equal(await store.consumeRecoveryCode(userId, 'b'), true);
        assert.equal(await store.consumeRecoveryCode(userId, 'b'), false);
        assert.equal(await store.consumeRecoveryCode(uniqueId('other'), 'a'), false);
        assert.equal(await store.consumeRecoveryCode(userId, 'missing'), false);
        assert.equal(await store.countRecoveryCodes(userId), 2);
      },
    },
    {
      name: 'consumeRecoveryCode is single-use under 50 concurrent callers',
      async run() {
        const userId = uniqueId('user');

        await store.replaceRecoveryCodes(userId, ['only', 'other']);
        const results = await times(50, () => store.consumeRecoveryCode(userId, 'only'));

        assert.equal(results.filter(Boolean).length, 1);
        assert.equal(await store.countRecoveryCodes(userId), 1);
      },
    },
    {
      name: 'concurrent consumption of different codes spends each exactly once',
      async run() {
        const userId = uniqueId('user');
        const codes = Array.from({ length: 10 }, (_, i) => `code-${i}`);

        await store.replaceRecoveryCodes(userId, codes);

        const results = await times(40, (i) =>
          store.consumeRecoveryCode(userId, codes[i % 10] ?? ''),
        );

        assert.equal(results.filter(Boolean).length, 10);
        assert.equal(await store.countRecoveryCodes(userId), 0);
      },
    },
    {
      name: 'replacing the recovery codes voids every old one at once',
      async run() {
        const userId = uniqueId('user');

        await store.replaceRecoveryCodes(userId, ['old-1', 'old-2']);
        await store.replaceRecoveryCodes(userId, ['new-1']);
        assert.equal(await store.consumeRecoveryCode(userId, 'old-1'), false);
        assert.equal(await store.countRecoveryCodes(userId), 1);
        assert.equal(await store.consumeRecoveryCode(userId, 'new-1'), true);
        await store.replaceRecoveryCodes(userId, ['again']);
        await store.replaceRecoveryCodes(userId, []);
        assert.equal(await store.countRecoveryCodes(userId), 0);
        assert.equal(await store.consumeRecoveryCode(userId, 'again'), false);
      },
    },
    {
      name: 'stores trusted devices and finds one only for its own user',
      async run() {
        const userId = uniqueId('user');
        const stored = device(userId, { epoch: 3 });

        await store.addTrustedDevice(stored, 5);
        assert.deepEqual(await store.findTrustedDevice(userId, stored.hash), stored);
        assert.equal(await store.findTrustedDevice(uniqueId('other'), stored.hash), null);
        assert.equal(await store.findTrustedDevice(userId, uniqueId('missing')), null);
      },
    },
    {
      name: 'keeps at most maxPerUser trusted devices, dropping the oldest',
      async run() {
        const userId = uniqueId('user');
        const other = device(uniqueId('user'));
        const now = systemClock.now();
        const devices = Array.from({ length: 4 }, (_, i) => device(userId, { createdAt: now + i }));

        await store.addTrustedDevice(other, 2);

        for (const d of devices) await store.addTrustedDevice(d, 2);

        const found = await Promise.all(
          devices.map((d) => store.findTrustedDevice(userId, d.hash)),
        );

        assert.deepEqual(
          found.map((d) => d !== null),
          [false, false, true, true],
        );

        assert.notEqual(await store.findTrustedDevice(other.userId, other.hash), null);
      },
    },
    {
      name: 'deletes every trusted device of a user and no one else',
      async run() {
        const userId = uniqueId('user');
        const mine = [device(userId), device(userId)];
        const theirs = device(uniqueId('user'));

        for (const d of [...mine, theirs]) await store.addTrustedDevice(d, 5);

        await store.deleteTrustedDevices(userId);

        for (const d of mine) assert.equal(await store.findTrustedDevice(userId, d.hash), null);

        assert.notEqual(await store.findTrustedDevice(theirs.userId, theirs.hash), null);
      },
    },
    {
      name: 'stores, replaces and finds a step-up proof per session',
      async run() {
        const sessionId = uniqueId('session');
        const userId = uniqueId('user');
        const expiresAt = systemClock.now() + 60_000;

        assert.equal(await store.findStepUp(sessionId), null);
        await store.putStepUp({ sessionId, userId, expiresAt });
        await store.putStepUp({ sessionId, userId, expiresAt: expiresAt + 1000 });

        assert.deepEqual(await store.findStepUp(sessionId), {
          sessionId,
          userId,
          expiresAt: expiresAt + 1000,
        });

        assert.equal(await store.findStepUp(uniqueId('session')), null);
      },
    },
  ];
}
