// The per-user session cap: every session it evicts is returned on the issued
// session and reported to `onSessionsRevoked` with reason `evicted`, once.
import { describe, expect, it } from 'vitest';

import type { Logger } from '../../src/ports/logger';
import type { RevocationReason } from '../../src';
import { meta, PASSWORD, setup } from './setup';

const EMAIL = 'ada@example.com';

interface RevokedCall {
  readonly userId: string;
  readonly sessionIds: readonly string[];
  readonly reason: RevocationReason;
}

function cappedApp(maxPerUser: number, extra: { logger?: Logger; throwing?: boolean } = {}) {
  const calls: RevokedCall[] = [];

  const t = setup({
    session: { maxPerUser },
    ...(extra.logger ? { logger: extra.logger } : {}),
    hooks: {
      onSessionsRevoked: ({ userId, sessionIds, reason }) => {
        calls.push({ userId, sessionIds: [...sessionIds], reason });

        if (extra.throwing) throw new Error('socket registry down');
      },
    },
  });

  async function login(ip = '203.0.113.7') {
    const result = await t.auth.login({ email: EMAIL, password: PASSWORD, meta: meta(ip) });

    if (!result.ok || result.value.kind !== 'session') throw new Error('login failed');

    return result.value.session;
  }

  const evictions = () => calls.filter((call) => call.reason === 'evicted');

  return { ...t, calls, evictions, login };
}

describe('the per-user session cap', () => {
  it('returns the evicted ids and reports them to the hooks once, with reason evicted', async () => {
    const t = cappedApp(2);
    const first = await t.signedInUser(EMAIL);

    t.clock.advance(1000);
    const second = await t.login();

    t.clock.advance(1000);
    const third = await t.login();

    expect(second.evicted).toEqual([]);
    expect(third.evicted).toEqual([first.session.id]);

    expect(t.evictions()).toEqual([
      { userId: first.session.userId, sessionIds: [first.session.id], reason: 'evicted' },
    ]);

    expect(await t.sessionOf(first.token)).toBeNull();
    expect(await t.sessionOf(second.token)).not.toBeNull();
    expect(await t.sessionOf(third.token)).not.toBeNull();
  });

  it('neither returns nor reports anything under the cap', async () => {
    const t = cappedApp(3);

    await t.signedInUser(EMAIL);
    t.clock.advance(1000);
    const second = await t.login();

    t.clock.advance(1000);
    const third = await t.login();

    expect(second.evicted).toEqual([]);
    expect(third.evicted).toEqual([]);
    expect(t.calls).toEqual([]);
  });

  it('reports each session evicted by sign-ins racing at the cap exactly once', async () => {
    const t = cappedApp(2);
    const first = await t.signedInUser(EMAIL);
    const existing = [first];

    t.clock.advance(1000);
    existing.push(await t.login());
    t.clock.advance(1000);

    const raced = await Promise.all(
      ['198.51.100.1', '198.51.100.2', '198.51.100.3', '198.51.100.4'].map((ip) => t.login(ip)),
    );

    const created = [...existing.map((s) => s.session.id), ...raced.map((s) => s.session.id)];

    const live = new Set(
      (await t.stores.sessions.listByUser(first.session.userId)).map((s) => s.id),
    );

    const gone = created.filter((id) => !live.has(id)).sort();
    const reported = t.evictions().flatMap((call) => call.sessionIds);
    const returned = raced.flatMap((issued) => issued.evicted);

    expect(live.size).toBeLessThanOrEqual(2);
    expect(new Set(reported).size).toBe(reported.length);
    expect([...reported].sort()).toEqual(gone);
    expect([...returned].sort()).toEqual(gone);

    for (const call of t.evictions()) expect(call.sessionIds.length).toBeGreaterThan(0);
  });

  it('still signs in, and logs, when the hook throws on an eviction', async () => {
    const lines: string[] = [];

    const logger: Logger = {
      warn: (message) => void lines.push(message),
      error: (message) => void lines.push(message),
    };

    const t = cappedApp(1, { logger, throwing: true });
    const first = await t.signedInUser(EMAIL);

    t.clock.advance(1000);
    const second = await t.login();

    expect(second.evicted).toEqual([first.session.id]);
    expect(t.evictions()).toHaveLength(1);
    expect(await t.sessionOf(second.token)).not.toBeNull();
    expect(await t.sessionOf(first.token)).toBeNull();
    expect(lines).toContain('onSessionsRevoked hook failed');
  });
});
