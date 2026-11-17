// A004: account enumeration by timing.
//
// An attacker times the answers: a password hash takes tens of milliseconds and a
// missing row takes one, so a door that skips work for unknown addresses tells
// them apart even when the answer text is the same.
//
// Stopped by: flows/login.ts (same store calls for every address, a full verify against a
//   dummy hash for unknown ones), password/verify.ts, tokens/one-time-tokens.ts
//   (same HMAC and lookup for an unknown user), throttle/counter-keys.ts (keys from
//   the address, never the user id), core/auth-core.ts (mail is handed over, never
//   awaited), flows/register.ts (everything after the insert runs off the response
//   path), auth-prisma src/user-store.ts (a taken address is a skipped insert, not a
//   failed statement). Checked by counting calls, not wall-clock
//   time, so CI cannot flake: tests/timing/benchmark.ts (`bun run bench:timing`)
//   measures the clock.
// Learn: Enumeration (/auth/learn/enumeration/)
import { describe, expect, it } from 'vitest';

import { cryptoRandom } from '../../src/crypto/random';
import { NO_SUCH_USER_ID } from '../../src/ports/stores';
import { manualClock, MemoryTokenStore, plainHasher } from '../../src/testing';
import { OneTimeTokens } from '../../src/tokens/one-time-tokens';
import {
  countingHasher,
  EMAIL,
  meta,
  onFakeClock,
  PASSWORD,
  queued,
  recordStoreCalls,
  registered,
  settled,
  setup,
} from './support';

describe('A004: account enumeration by timing', () => {
  it('pays a full verify for an unknown address', async () => {
    let verifies = 0;
    const base = plainHasher();

    const hasher = {
      ...base,
      verify: async (h: string, p: string) => (verifies++, base.verify(h, p)),
    };

    const { auth } = setup({ password: { hasher, breachCheck: false } });

    await auth.login({ email: 'nobody@example.com', password: PASSWORD, meta: meta() });
    expect(verifies).toBe(1);
  });

  it('makes the same calls on every store, and one verify, for a known, an unknown and a locked address', async () => {
    const { hasher, verified } = countingHasher();
    const env = await registered({ password: { hasher, breachCheck: false } });
    const { calls } = recordStoreCalls(env.stores);

    const trace = async (email: string, ip: string) => {
      calls.length = 0;
      verified.length = 0;
      await env.auth.login({ email, password: 'wrong passphrase!', meta: meta(ip) });

      return { calls: [...calls], verifies: verified.length };
    };

    const known = await trace(EMAIL, '192.0.2.1');
    const unknown = await trace('ghost@example.com', '192.0.2.1');

    expect(unknown).toEqual(known);
    expect(known.verifies).toBe(1);

    // Lock both addresses (an unknown address locks exactly like a known one).
    for (let i = 0; i < 11; i++) {
      const ip = `192.0.2.${10 + i}`;

      await env.auth.login({ email: EMAIL, password: 'wrong passphrase!', meta: meta(ip) });

      await env.auth.login({
        email: 'ghost@example.com',
        password: 'wrong passphrase!',
        meta: meta(ip),
      });
    }

    const knownLocked = await trace(EMAIL, '198.51.100.1');
    const unknownLocked = await trace('ghost@example.com', '198.51.100.1');

    expect(unknownLocked).toEqual(knownLocked);
    expect(knownLocked.verifies).toBe(1);

    // Under a lock the gate stops before it spends the (account, IP) and the
    // account budgets, so it makes fewer counter calls than an open account.
    // That says "locked", which an unknown address is too after the same
    // failures, never "exists": every other store call and the verify match.
    const outsideCounters = (t: { calls: string[] }) =>
      t.calls.filter((call) => !call.startsWith('counters.'));

    expect(outsideCounters(knownLocked)).toEqual(outsideCounters(known));
  });

  it('does not wait for the lockout audit row or mail before answering', async () => {
    const env = setup();

    await env.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });
    // From now on the mailer hangs forever.
    env.mailer.send = () => new Promise<void>(() => undefined);

    for (let i = 0; i < 10; i++)
      await env.auth.login({
        email: EMAIL,
        password: 'wrong passphrase!',
        meta: meta(`192.0.2.${i}`),
      });

    // The eleventh attempt sets the lock; the mailer never resolves, the login must still answer.
    const answer = await onFakeClock(() =>
      env.auth.login({ email: EMAIL, password: 'wrong passphrase!', meta: meta('192.0.2.99') }),
    );

    expect(answer !== 'held up' && !answer.ok && answer.reason).toBe('locked');
  });

  it('makes the same store calls on the request path of a reset for a known and an unknown address', async () => {
    const t = queued();

    await t.signedInUser(EMAIL);

    const { calls } = recordStoreCalls(t.stores);

    const trace = async (email: string) => {
      calls.length = 0;
      await t.auth.requestPasswordReset({ email, meta: meta() });

      return [...calls];
    };

    // The lookup, the token and the mail happen in the job, off the request path.
    expect(await trace('ghost@example.com')).toEqual(await trace(EMAIL));
  });

  // Not the same sequence: a taken address looks the owner up where a new
  // account writes its verification token. The test pins both sequences so
  // any other drift fails; the next test shows the answer waits on neither.
  // Both first look for a hold on the address (an email change away from it
  // can still be reverted); A061 pins a held address against these.
  it('hashes the password, makes the same number of store round trips and hands over one mail at sign-up, taken address or new', async () => {
    let hashes = 0;
    const base = plainHasher();
    const hasher = { ...base, hash: async (p: string) => (hashes++, base.hash(p)) };
    const env = setup({ password: { hasher, breachCheck: false } });

    await env.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });
    await settled();

    const { calls } = recordStoreCalls(env.stores);

    const trace = async (email: string) => {
      calls.length = 0;
      hashes = 0;

      const mailsBefore = env.mailer.sent.length;

      await env.auth.register({ email, password: PASSWORD, meta: meta() });
      await settled();

      return { calls: [...calls], hashes, mails: env.mailer.sent.length - mailsBefore };
    };

    const taken = await trace('ADA@example.com');
    const fresh = await trace('new@example.com');

    expect(taken).toEqual({
      calls: ['counters.increment', 'tokens.find', 'users.create', 'users.findCredentialByEmail'],
      hashes: 1,
      mails: 1,
    });

    expect(fresh).toEqual({
      calls: ['counters.increment', 'tokens.find', 'users.create', 'tokens.put'],
      hashes: 1,
      mails: 1,
    });
  });

  // On real stores the two sequences cost different times (a failed or skipped
  // insert and a read, against an insert and a write), so the answer must not
  // wait on anything after the insert: the owner lookup, the verification
  // token, the mail and the audit event all run off the response path.
  it('answers a sign-up without waiting on any store call after the insert, taken address or new', async () => {
    const env = await registered();
    const hang = () => new Promise<never>(() => undefined);

    env.stores.users.findCredentialByEmail = hang;
    env.stores.tokens.put = hang;
    env.audit.emit = hang;

    const { calls } = recordStoreCalls(env.stores);

    const answer = async (email: string) => {
      calls.length = 0;

      const result = await onFakeClock(() =>
        env.auth.register({ email, password: PASSWORD, meta: meta() }),
      );

      return { result, awaited: calls.slice(0, 3) };
    };

    const taken = await answer('ADA@example.com');
    const fresh = await answer('new@example.com');

    expect(taken).toEqual({
      result: { ok: true, value: { session: null } },
      awaited: ['counters.increment', 'tokens.find', 'users.create'],
    });

    expect(fresh).toEqual(taken);
  });

  it('makes the same token store lookup for an unknown user as for a known one', async () => {
    const lookups: string[] = [];
    const store = new MemoryTokenStore();

    const spy = Object.assign(Object.create(store) as MemoryTokenStore, {
      findByUser: (purpose: string, userId: string) => (
        lookups.push(userId),
        store.findByUser(purpose, userId)
      ),
    });

    const secret = new TextEncoder().encode('server-secret-server-secret-0000');
    const spied = new OneTimeTokens(spy, manualClock(), cryptoRandom, secret);

    await spied.redeemCode('reset', null, '12345678', 5);
    await spied.redeemCode('reset', 'user-1', '12345678', 5);
    expect(lookups).toEqual([NO_SUCH_USER_ID, 'user-1']);
  });
});
