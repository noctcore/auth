import { describe, expect, it, vi } from 'vitest';
import { createAuth, sha256Hex, type AuthMailEvent, type StoredSession } from '../../src';
import {
  invitations,
  type AcceptedInvitation,
  type InvitationsOptions,
} from '../../src/plugins/invitations';
import { MemoryInvitationStore, plainHasher } from '../../src/testing';
import { SECRET, setup } from '../flows/setup';
import { invitationApp, meta, PASSWORD, SCOPE } from './setup';

const DAY = 24 * 60 * 60_000;
const url = (token: string) => `https://app.example/invite#${token}`;

function options(overrides: Partial<InvitationsOptions> = {}): InvitationsOptions {
  return {
    store: new MemoryInvitationStore(),
    authorize: () => true,
    onAccept: () => undefined,
    url,
    ...overrides,
  };
}

function recordingLogger() {
  const errors: Array<{ message: string; context: unknown }> = [];

  return {
    errors,
    logger: {
      debug: () => undefined,
      info: () => undefined,
      warn: () => undefined,
      error: (message: string, context?: unknown) => void errors.push({ message, context }),
    },
  };
}

describe('invitations options', () => {
  it('refuses a missing store, authorize or onAccept', () => {
    expect(() => invitations(options({ store: undefined as never }))).toThrow(
      'invitations: store is required',
    );

    expect(() => invitations(options({ authorize: undefined as never }))).toThrow(
      'invitations: authorize is required, so creating is never open',
    );

    expect(() => invitations(options({ onAccept: undefined as never }))).toThrow(
      'invitations: onAccept is required',
    );
  });

  it('refuses a url that is missing, relative, drops the token or puts it in the query string', () => {
    expect(() => invitations(options({ url: undefined as never }))).toThrow(
      'invitations: url is required',
    );

    expect(() => invitations(options({ url: (t) => `/invite#${t}` }))).toThrow(
      'invitations: url must return an absolute URL',
    );

    expect(() => invitations(options({ url: () => 'https://app.example/invite' }))).toThrow(
      'invitations: url must carry the token',
    );

    expect(() => invitations(options({ url: (t) => `https://app.example/i?token=${t}` }))).toThrow(
      'invitations: url must put the token in the path or the fragment, never the query string',
    );

    expect(() =>
      invitations(options({ url: (t) => `https://app.example/i/${t}?x=1` })),
    ).not.toThrow();
  });

  it('caps the lifetime at 30 days and refuses an empty one', () => {
    expect(() => invitations(options({ ttl: 0 }))).toThrow(
      'invitations: ttl must be positive and at most 30 days',
    );

    expect(() => invitations(options({ ttl: 30 * DAY + 1 }))).toThrow(
      'invitations: ttl must be positive and at most 30 days',
    );

    expect(() => invitations(options({ ttl: '30d' }))).not.toThrow();
  });

  it('refuses a limit that would never count or never refuse', () => {
    for (const name of ['perInviter', 'perAddress', 'perIp'] as const) {
      expect(() => invitations(options({ [name]: { limit: 0, window: '1m' } }))).toThrow(
        `invitations: ${name}.limit must be a positive integer`,
      );

      expect(() => invitations(options({ [name]: { limit: 1.5, window: '1m' } }))).toThrow(
        `invitations: ${name}.limit must be a positive integer`,
      );

      expect(() => invitations(options({ [name]: { limit: 1, window: 0 } }))).toThrow(
        `invitations: ${name}.window must be positive`,
      );
    }
  });

  it('refuses an acceptWithoutSession that is not true or false', () => {
    expect(() => invitations(options({ acceptWithoutSession: 'yes' as never }))).toThrow(
      'invitations: acceptWithoutSession must be true or false',
    );

    expect(() => invitations(options({ acceptWithoutSession: true }))).not.toThrow();
  });

  it('binds one plugin instance to one createAuth', () => {
    const plugin = invitations(options());

    setup({ plugins: [plugin] });

    expect(() => setup({ plugins: [plugin] })).toThrow(
      'invitations: one plugin instance per createAuth',
    );
  });
});

describe('invitations create', () => {
  it('stores the SHA-256 of the token, mails the link and audits the invitation', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });
    const now = t.clock.now();

    const result = await t.auth.invitations.create({
      session: inviter.session,
      scope: SCOPE,
      email: '  Bob@Example.com ',
      payload: { role: 'admin' },
      meta: meta(),
    });

    expect(result.ok).toBe(true);

    const invitation = result.ok ? result.value.invitation : null;
    const token = t.mailedToken();
    const mail = t.mailer.last('invitation') as Extract<AuthMailEvent, { type: 'invitation' }>;

    expect(invitation?.id).toMatch(/^[0-9a-f]{32}$/u);

    expect(invitation).toEqual({
      id: invitation?.id,
      scope: SCOPE,
      email: 'bob@example.com',
      inviterId: inviter.userId,
      payload: { role: 'admin' },
      createdAt: new Date(now),
      expiresAt: new Date(now + 7 * DAY),
    });

    expect(token).toMatch(/^[0-9a-f]{64}$/u);

    expect(mail).toMatchObject({
      to: 'bob@example.com',
      scope: SCOPE,
      inviterId: inviter.userId,
      url: `https://app.example/invite#${token}`,
      expiresAt: new Date(now + 7 * DAY),
    });

    expect(mail).not.toHaveProperty('userId');

    const stored = await t.store.findByHash(sha256Hex(token));

    expect(stored).toMatchObject({ id: invitation?.id, email: 'bob@example.com' });
    expect(JSON.stringify(stored)).not.toContain(token);

    expect(t.authorize.mock.lastCall?.[0]).toMatchObject({
      user: { id: inviter.userId },
      scope: SCOPE,
      action: 'create',
      email: 'bob@example.com',
      payload: { role: 'admin' },
    });

    expect(t.audit.events.at(-1)).toMatchObject({
      type: 'invitation.created',
      userId: inviter.userId,
      data: { scope: SCOPE, invitation: invitation?.id },
    });
  });

  it('keeps the payload empty when none is given and honours a custom lifetime', async () => {
    const t = invitationApp({ ttl: '1h' });
    const inviter = await t.user({ canInvite: true });

    const result = await t.auth.invitations.create({
      session: inviter.session,
      scope: SCOPE,
      email: 'bob@example.com',
      meta: meta(),
    });

    expect(result.ok && result.value.invitation).toMatchObject({
      payload: {},
      expiresAt: new Date(t.clock.now() + 60 * 60_000),
    });
  });

  it('sends no second mail for a live invitation to the same scope and address', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });

    await t.invite(inviter, 'bob@example.com');

    const mails = t.mailer.sent.length;

    const again = await t.auth.invitations.create({
      session: inviter.session,
      scope: SCOPE,
      email: 'BOB@example.com',
      meta: meta(),
    });

    expect(again).toEqual({ ok: true, value: { invitation: null } });
    expect(t.mailer.sent).toHaveLength(mails);

    expect(t.audit.events.at(-1)).toMatchObject({
      type: 'invitation.deduplicated',
      userId: inviter.userId,
      data: { scope: SCOPE },
    });
  });

  it('refuses an invalid address, an unknown inviter and a user the app does not allow', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });
    const other = await t.user();
    const input = { scope: SCOPE, email: 'bob@example.com', meta: meta() };

    expect(
      await t.auth.invitations.create({ ...input, session: inviter.session, email: 'nope' }),
    ).toMatchObject({ ok: false, code: 'invalid_email', reason: 'invalid_email' });

    const ghost = { ...inviter.session, userId: 'ghost' } as StoredSession<Record<string, never>>;

    expect(await t.auth.invitations.create({ ...input, session: ghost })).toMatchObject({
      code: 'forbidden',
      reason: 'inviter_missing',
    });

    expect(await t.auth.invitations.create({ ...input, session: other.session })).toMatchObject({
      code: 'forbidden',
      reason: 'not_allowed',
    });

    expect(t.mailer.last('invitation')).toBeUndefined();

    expect(t.audit.events.filter((e) => e.type === 'invitation.refused')).toEqual([
      expect.objectContaining({ userId: inviter.userId, reason: 'invalid_email' }),
      expect.objectContaining({ userId: 'ghost', reason: 'inviter_missing' }),
      expect.objectContaining({ userId: other.userId, reason: 'not_allowed' }),
    ]);
  });

  it('refuses when authorize throws or answers anything but true, and logs no address', async () => {
    const { errors, logger } = recordingLogger();
    let answer: unknown = 'yes';

    const t = invitationApp(
      {
        authorize: () => {
          if (answer === 'throw') throw new Error('policy service down');

          return answer as boolean;
        },
      },
      { logger },
    );

    const inviter = await t.user();

    const input = {
      session: inviter.session,
      scope: SCOPE,
      email: 'bob@example.com',
      meta: meta(),
    };

    expect(await t.auth.invitations.create(input)).toMatchObject({ reason: 'not_allowed' });

    answer = 'throw';
    expect(await t.auth.invitations.create(input)).toMatchObject({ reason: 'not_allowed' });

    expect(errors).toHaveLength(1);

    expect(errors[0]).toMatchObject({
      message: 'Invitation permission check failed',
      context: { action: 'create' },
    });

    expect(Object.keys(errors[0]?.context ?? {})).toEqual(['action', 'error']);

    expect(JSON.stringify(errors)).not.toContain('bob@');
  });

  it('limits creates per IP, per inviter and per address, auditing each window once', async () => {
    const t = invitationApp({
      perIp: { limit: 2, window: '1m' },
      perInviter: { limit: 3, window: '1h' },
      perAddress: { limit: 1, window: '1d' },
    });

    const inviter = await t.user({ canInvite: true });

    const create = (email: string, ip = '203.0.113.7', scope = SCOPE) =>
      t.auth.invitations.create({ session: inviter.session, scope, email, meta: meta(ip) });

    expect((await create('a@example.com')).ok).toBe(true);

    expect(await create('a@example.com', '203.0.113.8', 'org_2')).toMatchObject({
      code: 'rate_limited',
      reason: 'rate_limited:invitation-address',
    });

    expect((await create('b@example.com')).ok).toBe(true);

    expect(await create('c@example.com')).toMatchObject({
      code: 'rate_limited',
      reason: 'rate_limited:invitation-ip',
      retryAfterSeconds: 60,
    });

    expect(await create('d@example.com')).toMatchObject({ reason: 'rate_limited:invitation-ip' });

    expect(await create('e@example.com', '203.0.113.9')).toMatchObject({
      reason: 'rate_limited:invitation-inviter',
    });

    expect(
      t.audit.events.filter((e) => e.type === 'rate_limit.exceeded').map((e) => e.reason),
    ).toEqual(['invitation-address', 'invitation-ip', 'invitation-inviter']);
  });
});

describe('invitations mail', () => {
  it('logs a failed invitation mail without a user id or the address', async () => {
    const { errors, logger } = recordingLogger();
    const t = invitationApp({}, { logger });
    const inviter = await t.user({ canInvite: true });

    vi.spyOn(t.mailer, 'send').mockRejectedValueOnce(new Error('smtp down'));

    const result = await t.auth.invitations.create({
      session: inviter.session,
      scope: SCOPE,
      email: 'bob@example.com',
      meta: meta(),
    });

    expect(result.ok).toBe(true);
    await vi.waitFor(() => expect(errors).toHaveLength(1));
    expect(errors[0]).toMatchObject({ message: 'Mailer failed', context: { type: 'invitation' } });
    expect(errors[0]?.context).not.toHaveProperty('userId');
    expect(JSON.stringify(errors)).not.toContain('bob@');
  });
});

describe('invitations throttle keys', () => {
  it('counts the address under its keyed hash, and the IP and inviter as they are', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });
    const increment = vi.spyOn(t.stores.counters, 'increment');

    await t.invite(inviter, 'bob@example.com');

    const addressKey = t.auth.context.keyedHash('invitation-address', 'bob@example.com');

    expect(addressKey).not.toBe(t.auth.context.keyedHash('invitation', 'bob@example.com'));

    expect(increment.mock.calls.map(([key]) => key)).toEqual([
      'rl:invitation-ip:203.0.113.7',
      `rl:invitation-inviter:${inviter.userId}`,
      `rl:invitation-address:${addressKey}`,
    ]);
  });
});

describe('invitations list and revoke', () => {
  it('lists the live invitations of a scope without their hashes', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });
    const { invitation } = await t.invite(inviter, 'bob@example.com');

    await t.invite(inviter, 'eve@example.com', 'org_2');

    const listed = await t.auth.invitations.list({
      session: inviter.session,
      scope: SCOPE,
      meta: meta(),
    });

    expect(listed).toEqual({ ok: true, value: [invitation] });

    expect(t.authorize.mock.lastCall?.[0]).toEqual({
      user: { id: inviter.userId, email: inviter.email, emailVerified: true },
      scope: SCOPE,
      action: 'list',
    });

    t.clock.advance(7 * DAY);

    expect(
      await t.auth.invitations.list({ session: inviter.session, scope: SCOPE, meta: meta() }),
    ).toEqual({ ok: true, value: [] });
  });

  it('revokes an invitation so its link no longer works', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });
    const bob = await t.user({ email: 'bob@example.com' });
    const { token, invitation } = await t.invite(inviter, bob.email);
    const input = { session: inviter.session, scope: SCOPE, id: invitation.id, meta: meta() };

    expect(await t.auth.invitations.revoke(input)).toEqual({ ok: true, value: undefined });
    expect(t.authorize).toHaveBeenLastCalledWith(expect.objectContaining({ action: 'revoke' }));

    expect(t.audit.events.at(-1)).toMatchObject({
      type: 'invitation.revoked',
      userId: inviter.userId,
      data: { scope: SCOPE, invitation: invitation.id },
    });

    expect(await t.auth.invitations.revoke(input)).toMatchObject({
      code: 'forbidden',
      reason: 'invitation_missing',
    });

    expect(
      await t.auth.invitations.accept({ session: bob.session, token, meta: meta() }),
    ).toMatchObject({ code: 'invalid_token', reason: 'unknown_token' });
  });

  it('refuses list and revoke to a user the app does not allow, or one that is gone', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });
    const other = await t.user();
    const { invitation } = await t.invite(inviter, 'bob@example.com');
    const ghost = { ...inviter.session, userId: 'ghost' } as StoredSession<Record<string, never>>;

    expect(
      await t.auth.invitations.list({ session: other.session, scope: SCOPE, meta: meta() }),
    ).toMatchObject({ code: 'forbidden', reason: 'not_allowed' });

    expect(
      await t.auth.invitations.revoke({
        session: other.session,
        scope: SCOPE,
        id: invitation.id,
        meta: meta(),
      }),
    ).toMatchObject({ code: 'forbidden', reason: 'not_allowed' });

    expect(
      await t.auth.invitations.list({ session: ghost, scope: SCOPE, meta: meta() }),
    ).toMatchObject({ code: 'forbidden', reason: 'inviter_missing' });

    expect(await t.store.listByScope(SCOPE, t.clock.now())).toHaveLength(1);
  });
});

describe('invitations accept', () => {
  it('accepts into the signed-in account with the invited, verified address', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });
    const bob = await t.user({ email: 'bob@example.com' });
    const { token, invitation } = await t.invite(inviter, 'Bob@Example.com');

    const result = await t.auth.invitations.accept({ session: bob.session, token, meta: meta() });

    expect(result).toEqual({ ok: true, value: invitation });

    expect(t.onAccept).toHaveBeenCalledTimes(1);

    expect(t.onAccept.mock.lastCall?.[0]).toMatchObject({
      user: { id: bob.userId, emailVerified: true },
      invitation: { id: invitation.id, payload: { role: 'member' } },
      created: false,
      meta: meta(),
    });

    expect(t.audit.events.at(-1)).toMatchObject({
      type: 'invitation.accepted',
      userId: bob.userId,
      data: { scope: SCOPE, invitation: invitation.id, created: false },
    });

    expect(await t.store.listByScope(SCOPE, t.clock.now())).toEqual([]);
    expect(await t.sessionOf(bob.token)).not.toBeNull();
  });

  it('refuses junk, unknown and expired tokens alike, without spending anything', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });
    const bob = await t.user({ email: 'bob@example.com' });
    const { token } = await t.invite(inviter, bob.email);

    const accept = (value: string) =>
      t.auth.invitations.accept({ session: bob.session, token: value, meta: meta() });

    expect(await accept('../../etc')).toEqual({
      ok: false,
      code: 'invalid_token',
      reason: 'malformed_token',
    });

    expect(await accept('a'.repeat(64))).toMatchObject({ reason: 'unknown_token' });

    t.clock.advance(7 * DAY - 1);
    expect(await t.store.findByHash(sha256Hex(token))).not.toBeNull();
    t.clock.advance(1);
    expect(await accept(token)).toMatchObject({ code: 'invalid_token', reason: 'expired_token' });
    expect(t.onAccept).not.toHaveBeenCalled();
  });

  it('refuses when both the account address and the stored one are invalid', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });
    const broken = await t.user();
    const raw = 'd'.repeat(64);
    const real = t.stores.users.findById.bind(t.stores.users);

    // An account whose stored address is not an address (written outside the core).
    vi.spyOn(t.stores.users, 'findById').mockImplementation(async (id) => {
      const found = await real(id);

      return found && id === broken.userId ? { ...found, email: 'not an address' } : found;
    });

    await t.store.create(
      {
        id: 'broken',
        hash: sha256Hex(raw),
        scope: SCOPE,
        email: 'also not an address',
        inviterId: inviter.userId,
        payload: {},
        createdAt: t.clock.now(),
        expiresAt: t.clock.now() + DAY,
      },
      t.clock.now(),
    );

    expect(
      await t.auth.invitations.accept({ session: broken.session, token: raw, meta: meta() }),
    ).toMatchObject({ ok: false, code: 'forbidden', reason: 'email_mismatch' });

    expect(t.onAccept).not.toHaveBeenCalled();
  });

  it('compares the stored address normalised too', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });
    const bob = await t.user({ email: 'bob@example.com' });
    const raw = 'c'.repeat(64);

    // A row written outside `create`, with the address as typed.
    await t.store.create(
      {
        id: 'raw',
        hash: sha256Hex(raw),
        scope: SCOPE,
        email: 'Bob@Example.com',
        inviterId: inviter.userId,
        payload: {},
        createdAt: t.clock.now(),
        expiresAt: t.clock.now() + DAY,
      },
      t.clock.now(),
    );

    expect(
      (await t.auth.invitations.accept({ session: bob.session, token: raw, meta: meta() })).ok,
    ).toBe(true);
  });

  it('refuses another address and an unverified one, and keeps the invitation', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });
    const eve = await t.user({ email: 'eve@example.com' });
    const bob = await t.user({ email: 'bob@example.com', verified: false });
    const { token } = await t.invite(inviter, 'bob@example.com');

    expect(
      await t.auth.invitations.accept({ session: eve.session, token, meta: meta() }),
    ).toMatchObject({ code: 'forbidden', reason: 'email_mismatch' });

    expect(
      await t.auth.invitations.accept({ session: bob.session, token, meta: meta() }),
    ).toMatchObject({ code: 'forbidden', reason: 'email_unverified' });

    const ghost = { ...bob.session, userId: 'ghost' } as StoredSession<Record<string, never>>;

    expect(await t.auth.invitations.accept({ session: ghost, token, meta: meta() })).toMatchObject({
      code: 'forbidden',
      reason: 'user_missing',
    });

    expect(t.audit.events.filter((e) => e.type === 'invitation.refused').at(-2)).toMatchObject({
      userId: bob.userId,
    });

    expect(await t.store.listByScope(SCOPE, t.clock.now())).toHaveLength(1);
    expect(t.onAccept).not.toHaveBeenCalled();
  });

  it('refuses a second accept and an invitation spent meanwhile', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });
    const bob = await t.user({ email: 'bob@example.com' });
    const { token } = await t.invite(inviter, bob.email);
    const input = { session: bob.session, token, meta: meta() };

    vi.spyOn(t.store, 'consume').mockResolvedValueOnce(null);

    expect(await t.auth.invitations.accept(input)).toMatchObject({
      code: 'invalid_token',
      reason: 'already_spent',
    });

    expect((await t.auth.invitations.accept(input)).ok).toBe(true);
    expect(await t.auth.invitations.accept(input)).toMatchObject({ reason: 'unknown_token' });
    expect(t.onAccept).toHaveBeenCalledTimes(1);
  });

  it('withdraws the invitation when the inviter lost the right or the account', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });
    const bob = await t.user({ email: 'bob@example.com' });
    const { token, invitation } = await t.invite(inviter, bob.email);

    t.allowed.delete(inviter.userId);

    expect(
      await t.auth.invitations.accept({ session: bob.session, token, meta: meta() }),
    ).toMatchObject({ code: 'invalid_token', reason: 'inviter_not_allowed' });

    expect(t.authorize.mock.lastCall?.[0]).toMatchObject({
      user: { id: inviter.userId },
      scope: SCOPE,
      action: 'create',
      email: 'bob@example.com',
      payload: invitation.payload,
    });

    expect(await t.store.listByScope(SCOPE, t.clock.now())).toEqual([]);

    t.allowed.add(inviter.userId);

    const second = await t.invite(inviter, bob.email);

    vi.spyOn(t.stores.users, 'findById').mockImplementation(async (id) =>
      id === inviter.userId ? null : { id, email: bob.email, emailVerified: true },
    );

    expect(
      await t.auth.invitations.accept({ session: bob.session, token: second.token, meta: meta() }),
    ).toMatchObject({ reason: 'inviter_not_allowed' });
  });

  it('withdraws the invitation of a deleted inviter even when the app allows everyone', async () => {
    const t = invitationApp({ authorize: () => true });
    const inviter = await t.user();
    const bob = await t.user({ email: 'bob@example.com' });
    const { token } = await t.invite(inviter, bob.email);
    const findById = t.stores.users.findById.bind(t.stores.users);

    vi.spyOn(t.stores.users, 'findById').mockImplementation(async (id) =>
      id === inviter.userId ? null : findById(id),
    );

    expect(
      await t.auth.invitations.accept({ session: bob.session, token, meta: meta() }),
    ).toMatchObject({ code: 'invalid_token', reason: 'inviter_not_allowed' });
  });

  it('skips the inviter check when the app turns it off', async () => {
    const t = invitationApp({ recheckInviter: false });
    const inviter = await t.user({ canInvite: true });
    const bob = await t.user({ email: 'bob@example.com' });
    const { token } = await t.invite(inviter, bob.email);

    t.allowed.delete(inviter.userId);
    t.authorize.mockClear();

    expect(
      (await t.auth.invitations.accept({ session: bob.session, token, meta: meta() })).ok,
    ).toBe(true);

    expect(t.authorize).not.toHaveBeenCalled();
  });

  it('lets a throwing onAccept reach the caller, with the invitation spent', async () => {
    const t = invitationApp({
      onAccept: () => {
        throw new Error('membership store down');
      },
    });

    const inviter = await t.user({ canInvite: true });
    const bob = await t.user({ email: 'bob@example.com' });
    const { token } = await t.invite(inviter, bob.email);

    await expect(
      t.auth.invitations.accept({ session: bob.session, token, meta: meta() }),
    ).rejects.toThrow('membership store down');

    expect(await t.store.listByScope(SCOPE, t.clock.now())).toEqual([]);
    expect(t.audit.types()).not.toContain('invitation.accepted');
  });

  it('refuses a null session while acceptWithoutSession is off, spending nothing', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });

    await t.user({ email: 'bob@example.com' });

    const { token } = await t.invite(inviter, 'bob@example.com');

    expect(await t.auth.invitations.accept({ session: null, token, meta: meta() })).toEqual({
      ok: false,
      code: 'forbidden',
      reason: 'session_required',
    });

    expect(t.onAccept).not.toHaveBeenCalled();
    expect(await t.store.listByScope(SCOPE, t.clock.now())).toHaveLength(1);
  });

  it('accepts an invitation issued before the server secret was rotated', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });
    const bob = await t.user({ email: 'bob@example.com' });
    const { token, invitation } = await t.invite(inviter, 'bob@example.com');

    // The same stores and invitation store, restarted under a new secret.
    const plugin = invitations({
      store: t.store,
      authorize: t.authorize,
      onAccept: t.onAccept,
      url,
    });

    const rotated = createAuth({
      stores: t.stores,
      password: { hasher: plainHasher(), breachCheck: false },
      secret: 'a-rotated-secret-that-is-also-32-bytes-or-more',
      urls: {
        resetPassword: (x) => `https://app.example/reset#${x}`,
        verifyEmail: (x) => `https://app.example/verify#${x}`,
      },
      mailer: t.mailer,
      audit: t.audit,
      clock: t.clock,
      plugins: [plugin],
    });

    expect(await rotated.invitations.accept({ session: bob.session, token, meta: meta() })).toEqual(
      { ok: true, value: invitation },
    );

    expect(t.onAccept).toHaveBeenCalledTimes(1);
  });

  it('still accepts an invitation stored under the keyed hash used before 0.6', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });
    const bob = await t.user({ email: 'bob@example.com' });
    const raw = 'e'.repeat(64);

    await t.store.create(
      {
        id: 'legacy',
        hash: t.auth.context.keyedHash('invitation', raw),
        scope: SCOPE,
        email: 'bob@example.com',
        inviterId: inviter.userId,
        payload: {},
        createdAt: t.clock.now(),
        expiresAt: t.clock.now() + DAY,
      },
      t.clock.now(),
    );

    expect(
      await t.auth.invitations.accept({ session: bob.session, token: raw, meta: meta() }),
    ).toMatchObject({ ok: true, value: { id: 'legacy' } });

    expect(await t.store.listByScope(SCOPE, t.clock.now())).toEqual([]);
  });

  it('finds a pre-0.6 row under a previous secret while previousSecret is set', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });
    const bob = await t.user({ email: 'bob@example.com' });
    const raw = 'f'.repeat(64);

    await t.store.create(
      {
        id: 'legacy-rotated',
        hash: t.auth.context.keyedHash('invitation', raw),
        scope: SCOPE,
        email: 'bob@example.com',
        inviterId: inviter.userId,
        payload: {},
        createdAt: t.clock.now(),
        expiresAt: t.clock.now() + DAY,
      },
      t.clock.now(),
    );

    const rotated = (previousSecret?: string) =>
      createAuth({
        stores: t.stores,
        password: { hasher: plainHasher(), breachCheck: false },
        secret: 'a-rotated-secret-that-is-also-32-bytes-or-more',
        ...(previousSecret === undefined ? {} : { previousSecret }),
        urls: {
          resetPassword: (x) => `https://app.example/reset#${x}`,
          verifyEmail: (x) => `https://app.example/verify#${x}`,
        },
        mailer: t.mailer,
        audit: t.audit,
        clock: t.clock,
        plugins: [
          invitations({ store: t.store, authorize: t.authorize, onAccept: t.onAccept, url }),
        ],
      });

    expect(
      await rotated().invitations.accept({ session: bob.session, token: raw, meta: meta() }),
    ).toMatchObject({ ok: false, code: 'invalid_token' });

    expect(
      await rotated(SECRET).invitations.accept({ session: bob.session, token: raw, meta: meta() }),
    ).toMatchObject({ ok: true, value: { id: 'legacy-rotated' } });
  });

  it('accepts an account that already belongs to another scope, leaving the move to onAccept', async () => {
    const memberOf = new Map<string, string>();

    const t = invitationApp({
      // The app's rule: one scope per account, so accepting moves it.
      onAccept: ({ user, invitation }: AcceptedInvitation) =>
        void memberOf.set(user.id, invitation.scope),
    });

    const inviter = await t.user({ canInvite: true });
    const bob = await t.user({ email: 'bob@example.com' });

    memberOf.set(bob.userId, 'org_old');

    const { token } = await t.invite(inviter, 'bob@example.com', 'org_new');

    expect(
      await t.auth.invitations.accept({ session: bob.session, token, meta: meta() }),
    ).toMatchObject({ ok: true, value: { scope: 'org_new' } });

    expect(memberOf.get(bob.userId)).toBe('org_new');
  });

  it('limits accepts per IP', async () => {
    const t = invitationApp({ perIp: { limit: 1, window: '1m' } });
    const bob = await t.user({ email: 'bob@example.com' });

    const accept = () =>
      t.auth.invitations.accept({ session: bob.session, token: 'a'.repeat(64), meta: meta() });

    expect(await accept()).toMatchObject({ reason: 'unknown_token' });
    expect(await accept()).toMatchObject({ reason: 'rate_limited:invitation-ip' });
  });
});

describe('invitations accept without a session', () => {
  it('accepts into the account holding the invited, verified address, and signs nobody in', async () => {
    const t = invitationApp({ acceptWithoutSession: true });
    const inviter = await t.user({ canInvite: true });
    const bob = await t.user({ email: 'bob@example.com' });
    const { token, invitation } = await t.invite(inviter, 'Bob@Example.com');
    const created = () => t.audit.types().filter((type) => type === 'session.created').length;
    const before = created();

    expect(await t.auth.invitations.accept({ session: null, token, meta: meta() })).toEqual({
      ok: true,
      value: invitation,
    });

    const accepted = t.onAccept.mock.lastCall?.[0];

    expect(accepted).toMatchObject({
      user: { id: bob.userId, emailVerified: true },
      invitation: { id: invitation.id },
      created: false,
    });

    expect(accepted?.user).not.toHaveProperty('passwordHash');

    expect(t.audit.events.at(-1)).toMatchObject({
      type: 'invitation.accepted',
      userId: bob.userId,
      data: { scope: SCOPE, invitation: invitation.id, created: false, withoutSession: true },
    });

    expect(created()).toBe(before);
    expect(await t.store.listByScope(SCOPE, t.clock.now())).toEqual([]);
  });

  it('refuses an address with no account, spending nothing, so register can still use it', async () => {
    const t = invitationApp({ acceptWithoutSession: true });
    const inviter = await t.user({ canInvite: true });
    const { token } = await t.invite(inviter, 'new@example.com');

    expect(await t.auth.invitations.accept({ session: null, token, meta: meta() })).toEqual({
      ok: false,
      code: 'forbidden',
      reason: 'account_missing',
    });

    expect(
      await t.auth.invitations.register({ token, password: PASSWORD, meta: meta() }),
    ).toMatchObject({ ok: true });
  });

  it('refuses a stored address that is not an address, as having no account', async () => {
    const t = invitationApp({ acceptWithoutSession: true });
    const inviter = await t.user({ canInvite: true });
    const raw = 'f'.repeat(64);

    await t.store.create(
      {
        id: 'corrupt',
        hash: sha256Hex(raw),
        scope: SCOPE,
        email: 'not an address',
        inviterId: inviter.userId,
        payload: {},
        createdAt: t.clock.now(),
        expiresAt: t.clock.now() + DAY,
      },
      t.clock.now(),
    );

    expect(await t.auth.invitations.accept({ session: null, token: raw, meta: meta() })).toEqual({
      ok: false,
      code: 'forbidden',
      reason: 'account_missing',
    });

    expect(t.onAccept).not.toHaveBeenCalled();
  });

  it('refuses a junk token and an inviter who lost the right, as with a session', async () => {
    const t = invitationApp({ acceptWithoutSession: true });
    const inviter = await t.user({ canInvite: true });

    await t.user({ email: 'bob@example.com' });

    expect(
      await t.auth.invitations.accept({ session: null, token: 'nope', meta: meta() }),
    ).toMatchObject({ code: 'invalid_token', reason: 'malformed_token' });

    const { token } = await t.invite(inviter, 'bob@example.com');

    t.allowed.delete(inviter.userId);

    expect(await t.auth.invitations.accept({ session: null, token, meta: meta() })).toMatchObject({
      code: 'invalid_token',
      reason: 'inviter_not_allowed',
    });

    expect(t.onAccept).not.toHaveBeenCalled();
  });

  it('still checks a session that is given against the invited address', async () => {
    const t = invitationApp({ acceptWithoutSession: true });
    const inviter = await t.user({ canInvite: true });
    const carol = await t.user({ email: 'carol@example.com' });

    await t.user({ email: 'bob@example.com' });

    const { token } = await t.invite(inviter, 'bob@example.com');

    expect(
      await t.auth.invitations.accept({ session: carol.session, token, meta: meta() }),
    ).toEqual({ ok: false, code: 'forbidden', reason: 'email_mismatch' });

    expect(await t.store.listByScope(SCOPE, t.clock.now())).toHaveLength(1);
  });
});

describe('invitations register', () => {
  it('creates the account verified, runs afterRegister and signs it in', async () => {
    const afterRegister = vi.fn((_context: { user: { id: string }; meta: unknown }) => undefined);
    const t = invitationApp({}, { hooks: { afterRegister } });
    const inviter = await t.user({ canInvite: true });
    const { token, invitation } = await t.invite(inviter, 'new@example.com');

    const result = await t.auth.invitations.register({ token, password: PASSWORD, meta: meta() });

    expect(result.ok).toBe(true);

    if (!result.ok) return;

    const user = await t.stores.users.findCredentialByEmail('new@example.com' as never);

    expect(user).toMatchObject({ emailVerified: true });
    expect(result.value.invitation).toEqual(invitation);
    expect(result.value.session.session).toMatchObject({ userId: user?.id });
    expect(await t.sessionOf(result.value.session.token)).not.toBeNull();

    expect(afterRegister.mock.lastCall?.[0]).toMatchObject({
      user: { id: user?.id, emailVerified: true },
      meta: meta(),
    });

    expect(t.onAccept.mock.lastCall?.[0]).toMatchObject({ created: true, user: { id: user?.id } });

    expect(t.audit.types().slice(-3)).toEqual([
      'register.created',
      'invitation.accepted',
      'session.created',
    ]);

    expect(t.audit.events.find((e) => e.type === 'invitation.accepted')).toMatchObject({
      userId: user?.id,
      data: { created: true },
    });

    expect(t.mailer.last('verify-email')?.to).not.toBe('new@example.com');

    expect(
      await t.auth.login({ email: 'new@example.com', password: PASSWORD, meta: meta() }),
    ).toMatchObject({ ok: true });
  });

  it('refuses a taken address without spending the invitation', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });

    await t.user({ email: 'bob@example.com' });

    const { token } = await t.invite(inviter, 'bob@example.com');

    expect(await t.auth.invitations.register({ token, password: PASSWORD, meta: meta() })).toEqual({
      ok: false,
      code: 'email_in_use',
      reason: 'email_in_use',
    });

    expect(await t.store.listByScope(SCOPE, t.clock.now())).toHaveLength(1);
  });

  it('refuses a password the policy refuses, before looking the address up', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });
    const { token } = await t.invite(inviter, 'new@example.com');
    const lookup = vi.spyOn(t.stores.users, 'findCredentialByEmail');

    expect(
      await t.auth.invitations.register({ token, password: 'short', meta: meta() }),
    ).toMatchObject({ ok: false, code: 'weak_password' });

    expect(lookup).not.toHaveBeenCalled();
    expect(t.audit.events.at(-1)).toMatchObject({ type: 'invitation.refused' });
    expect(t.audit.events.at(-1)).not.toHaveProperty('userId');
    expect(await t.store.listByScope(SCOPE, t.clock.now())).toHaveLength(1);
  });

  it('spends the invitation when the address is taken between the lookup and the create', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });
    const { token } = await t.invite(inviter, 'new@example.com');

    vi.spyOn(t.stores.users, 'create').mockResolvedValueOnce(null);

    expect(await t.auth.invitations.register({ token, password: PASSWORD, meta: meta() })).toEqual({
      ok: false,
      code: 'email_in_use',
      reason: 'email_in_use',
    });

    expect(await t.store.listByScope(SCOPE, t.clock.now())).toEqual([]);
    expect(t.onAccept).not.toHaveBeenCalled();
  });

  it('refuses a bad token, an inviter who lost the right, and a corrupt stored address', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });

    expect(
      await t.auth.invitations.register({ token: 'x', password: PASSWORD, meta: meta() }),
    ).toMatchObject({ code: 'invalid_token', reason: 'malformed_token' });

    const { token } = await t.invite(inviter, 'new@example.com');

    t.allowed.delete(inviter.userId);

    expect(
      await t.auth.invitations.register({ token, password: PASSWORD, meta: meta() }),
    ).toMatchObject({ code: 'invalid_token', reason: 'inviter_not_allowed' });

    const corrupt = 'b'.repeat(64);

    await t.store.create(
      {
        id: 'corrupt',
        hash: sha256Hex(corrupt),
        scope: SCOPE,
        email: 'not an address',
        inviterId: inviter.userId,
        payload: {},
        createdAt: t.clock.now(),
        expiresAt: t.clock.now() + DAY,
      },
      t.clock.now(),
    );

    expect(
      await t.auth.invitations.register({ token: corrupt, password: PASSWORD, meta: meta() }),
    ).toMatchObject({ code: 'invalid_token', reason: 'invitation_email_invalid' });
  });

  it('hands back the refusal when the session cannot be issued', async () => {
    const t = invitationApp(
      {},
      {
        hooks: {
          beforeSessionCreate: ({ via }) =>
            via === 'invitation'
              ? { refuse: true, code: 'second_factor_required', reason: 'enroll_first' }
              : undefined,
        },
      },
    );

    const inviter = await t.user({ canInvite: true });
    const { token } = await t.invite(inviter, 'new@example.com');

    expect(
      await t.auth.invitations.register({ token, password: PASSWORD, meta: meta() }),
    ).toMatchObject({ ok: false, code: 'second_factor_required' });

    expect(t.onAccept).toHaveBeenCalledTimes(1);
  });
});

describe('invitations after revocation', () => {
  it("deletes an inviter's invitations when all their sessions are revoked, not on a sign-out", async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });

    await t.invite(inviter, 'bob@example.com');
    await t.auth.logout({ token: inviter.token, meta: meta() });
    expect(await t.store.listByScope(SCOPE, t.clock.now())).toHaveLength(1);

    for (const reason of [
      'revoke-one',
      'revoke-others',
      'evicted',
      'email-verified',
      'two-factor-enabled',
    ]) {
      await t.auth.context.notifyRevoked(inviter.userId, [], reason);
    }

    expect(await t.store.listByScope(SCOPE, t.clock.now())).toHaveLength(1);

    await t.auth.context.revokeAllSessions(inviter.userId, 'revoke-all');
    expect(await t.store.listByScope(SCOPE, t.clock.now())).toEqual([]);
  });

  it('deletes only the scope a scoped revocation names, and every scope otherwise', async () => {
    const t = invitationApp();
    const inviter = await t.user({ canInvite: true });

    await t.invite(inviter, 'bob@example.com');
    await t.invite(inviter, 'bob@example.com', 'org_2');

    await t.auth.context.revokeAllSessions(inviter.userId, 'membership-changed', {
      scope: 'org_2',
    });

    expect(await t.store.listByScope(SCOPE, t.clock.now())).toHaveLength(1);
    expect(await t.store.listByScope('org_2', t.clock.now())).toEqual([]);

    await t.invite(inviter, 'bob@example.com', 'org_2');
    await t.auth.context.revokeAllSessions(inviter.userId, 'password-change');

    expect(await t.store.listByScope(SCOPE, t.clock.now())).toEqual([]);
    expect(await t.store.listByScope('org_2', t.clock.now())).toEqual([]);
  });
});
