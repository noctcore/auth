import { describe, expect, it, vi } from 'vitest';

import {
  membership,
  MEMBERSHIP_REVOCATION,
  type ManageContext,
} from '../../src/plugins/membership';
import type { MembershipStore } from '../../src/ports/membership';
import { membershipStoreConformance, MemoryMembershipStore } from '../../src/testing';
import { setup } from '../flows/setup';
import { acting, membershipApp, meta, PASSWORD, SCOPE } from './setup';

describe('membership options', () => {
  const store = new MemoryMembershipStore();

  it('refuses a missing store and an empty or malformed admin role list', () => {
    expect(() => membership({ store: undefined as never, adminRoles: ['admin'] })).toThrow(
      'membership: store is required',
    );

    for (const adminRoles of [[], [''], [42], [['admin']], ['admin', ''], 'admin', undefined])
      expect(() => membership({ store, adminRoles: adminRoles as never })).toThrow(
        'membership: adminRoles must list at least one role',
      );
  });

  it('binds one plugin instance to one createAuth', () => {
    const plugin = membership({ store, adminRoles: ['admin'] });

    setup({ plugins: [plugin] });

    expect(() => setup({ plugins: [plugin] })).toThrow(
      'membership: one plugin instance per createAuth',
    );
  });
});

describe('membership add', () => {
  it('adds a member and audits it without revoking anything', async () => {
    const t = membershipApp();
    const admin = await t.member('admin');
    const newcomer = await t.member(null);
    const added = await t.auth.membership.add({ ...acting(admin, newcomer), role: 'member' });

    expect(added).toEqual({
      ok: true,
      value: { scope: SCOPE, userId: newcomer.userId, role: 'member' },
    });

    expect(await t.sessionOf(newcomer.token)).not.toBeNull();

    expect(t.audit.events.at(-1)).toMatchObject({
      type: 'membership.added',
      userId: admin.userId,
      data: { scope: SCOPE, target: newcomer.userId, to: 'member' },
    });
  });

  it('refuses an existing member, an empty role and a non-admin actor', async () => {
    const t = membershipApp();
    const admin = await t.member('admin');
    const plain = await t.member('member');
    const outsider = await t.member(null);

    expect(await t.auth.membership.add({ ...acting(admin, plain), role: 'admin' })).toMatchObject({
      ok: false,
      code: 'forbidden',
      reason: 'already_member',
    });

    for (const role of ['', 7])
      expect(
        await t.auth.membership.add({ ...acting(admin, outsider), role: role as never }),
      ).toMatchObject({ code: 'forbidden', reason: 'invalid_role' });

    expect(
      await t.auth.membership.add({ ...acting(plain, outsider), role: 'member' }),
    ).toMatchObject({ code: 'forbidden', reason: 'not_allowed' });

    expect(await t.store.findMember(SCOPE, outsider.userId)).toBeNull();
  });

  it('refuses when the store says the user was added meanwhile', async () => {
    const t = membershipApp();
    const admin = await t.member('admin');
    const outsider = await t.member(null);

    vi.spyOn(t.store, 'addMember').mockResolvedValueOnce(false);

    expect(
      await t.auth.membership.add({ ...acting(admin, outsider), role: 'member' }),
    ).toMatchObject({ ok: false, code: 'forbidden', reason: 'already_member' });
  });
});

describe('membership changeRole', () => {
  it('changes the role and keeps every session by default', async () => {
    const t = membershipApp();
    const admin = await t.member('admin');
    const target = await t.member('member');
    const changed = await t.auth.membership.changeRole({ ...acting(admin, target), role: 'admin' });

    expect(changed.ok).toBe(true);
    expect((await t.store.findMember(SCOPE, target.userId))?.role).toBe('admin');
    expect(await t.sessionOf(target.token)).not.toBeNull();
    expect(t.audit.types()).not.toContain('sessions.revoked');
  });

  it('with revokeSessionsOnChange, revokes the member before and after the write and keeps the actor signed in', async () => {
    const revoked: Array<{ userId: string; reason: string; scope: string | undefined }> = [];

    const t = membershipApp(
      { revokeSessionsOnChange: true },
      {
        hooks: {
          onSessionsRevoked: ({ userId, reason, scope }) =>
            void revoked.push({ userId, reason, scope }),
        },
      },
    );

    const admin = await t.member('admin');
    const target = await t.member('member');
    const changed = await t.auth.membership.changeRole({ ...acting(admin, target), role: 'admin' });

    expect(changed).toEqual({
      ok: true,
      value: { scope: SCOPE, userId: target.userId, role: 'admin' },
    });

    expect((await t.store.findMember(SCOPE, target.userId))?.role).toBe('admin');
    expect(await t.sessionOf(target.token)).toBeNull();
    expect(await t.sessionOf(admin.token)).not.toBeNull();

    expect(revoked).toEqual([
      { userId: target.userId, reason: 'membership-changed', scope: SCOPE },
      { userId: target.userId, reason: 'membership-changed', scope: SCOPE },
    ]);

    expect(MEMBERSHIP_REVOCATION).toBe('membership-changed');

    expect(t.audit.events.at(-1)).toEqual({
      type: 'membership.role_changed',
      userId: admin.userId,
      data: { scope: SCOPE, target: target.userId, from: 'member', to: 'admin' },
      meta: meta(),
    });
  });

  it('writes and revokes nothing for the role the member already holds', async () => {
    const t = membershipApp({ revokeSessionsOnChange: true });
    const admin = await t.member('admin');
    const target = await t.member('member');
    const write = vi.spyOn(t.store, 'changeRole');
    const same = await t.auth.membership.changeRole({ ...acting(admin, target), role: 'member' });

    expect(same).toEqual({
      ok: true,
      value: { scope: SCOPE, userId: target.userId, role: 'member' },
    });

    expect(write).not.toHaveBeenCalled();
    expect(await t.sessionOf(target.token)).not.toBeNull();
    expect(t.audit.types()).not.toContain('membership.role_changed');
  });

  it('refuses to demote the last admin and revokes nothing', async () => {
    const t = membershipApp({ canManage: () => true });
    const lone = await t.member('owner');
    const helper = await t.member('member');
    const demoted = await t.auth.membership.changeRole({ ...acting(helper, lone), role: 'member' });

    expect(demoted).toEqual({ ok: false, code: 'last_admin', reason: 'last_admin' });
    expect(await t.sessionOf(lone.token)).not.toBeNull();

    expect(t.audit.events.at(-1)).toMatchObject({
      type: 'membership.refused',
      reason: 'last_admin',
      data: { scope: SCOPE, target: lone.userId, action: 'change-role' },
    });
  });

  it('refuses a target that is not a member or whose role changed meanwhile', async () => {
    const t = membershipApp();
    const admin = await t.member('admin');
    const target = await t.member('member');
    const outsider = await t.member(null);

    expect(
      await t.auth.membership.changeRole({ ...acting(admin, outsider), role: 'admin' }),
    ).toMatchObject({ code: 'forbidden', reason: 'target_missing' });

    vi.spyOn(t.store, 'changeRole').mockResolvedValueOnce('stale');

    expect(
      await t.auth.membership.changeRole({ ...acting(admin, target), role: 'admin' }),
    ).toMatchObject({ code: 'forbidden', reason: 'target_changed' });

    vi.spyOn(t.store, 'changeRole').mockResolvedValueOnce('missing');

    expect(
      await t.auth.membership.changeRole({ ...acting(admin, target), role: 'admin' }),
    ).toMatchObject({ code: 'forbidden', reason: 'target_missing' });

    expect(await t.sessionOf(target.token)).not.toBeNull();
  });

  it('asks canManage with what the store holds', async () => {
    const canManage = vi.fn(() => false);
    const t = membershipApp({ canManage });
    const admin = await t.member('admin');
    const target = await t.member('member');

    expect(
      await t.auth.membership.changeRole({ ...acting(admin, target), role: 'owner' }),
    ).toMatchObject({ code: 'forbidden', reason: 'not_allowed' });

    expect(canManage).toHaveBeenCalledWith({
      actor: { scope: SCOPE, userId: admin.userId, role: 'admin' },
      action: 'change-role',
      userId: target.userId,
      from: 'member',
      to: 'owner',
    });
  });
});

describe('membership remove', () => {
  it('removes the member, and revokes its sessions only with revokeSessionsOnChange', async () => {
    const quiet = membershipApp();
    const keeper = await quiet.member('admin');
    const kept = await quiet.member('member');

    expect((await quiet.auth.membership.remove(acting(keeper, kept))).ok).toBe(true);
    expect(await quiet.sessionOf(kept.token)).not.toBeNull();

    const t = membershipApp({ revokeSessionsOnChange: true });
    const admin = await t.member('admin');
    const target = await t.member('admin');

    expect(await t.auth.membership.remove(acting(admin, target))).toEqual({
      ok: true,
      value: undefined,
    });

    expect(await t.store.findMember(SCOPE, target.userId)).toBeNull();
    expect(await t.sessionOf(target.token)).toBeNull();

    expect(t.audit.events.at(-1)).toMatchObject({
      type: 'membership.removed',
      userId: admin.userId,
      data: { scope: SCOPE, target: target.userId, from: 'admin' },
    });
  });

  it('refuses to remove the last admin, or a member the store lost meanwhile', async () => {
    const t = membershipApp({ canManage: () => true });
    const lone = await t.member('admin');
    const plain = await t.member('member');

    expect(await t.auth.membership.remove(acting(plain, lone))).toMatchObject({
      code: 'last_admin',
    });

    vi.spyOn(t.store, 'removeMember').mockResolvedValueOnce('missing');

    expect(await t.auth.membership.remove(acting(lone, plain))).toMatchObject({
      code: 'forbidden',
      reason: 'target_missing',
    });

    expect(await t.sessionOf(lone.token)).not.toBeNull();
    expect(await t.sessionOf(plain.token)).not.toBeNull();
  });
});

describe('membership checks', () => {
  it('never asks canManage about a target that is missing, or already a member when adding', async () => {
    const canManage = vi.fn(() => true);
    const t = membershipApp({ canManage });
    const admin = await t.member('admin');
    const plain = await t.member('member');
    const outsider = await t.member(null);

    expect(await t.auth.membership.add({ ...acting(admin, plain), role: 'admin' })).toMatchObject({
      reason: 'already_member',
    });

    expect(await t.auth.membership.remove(acting(admin, outsider))).toMatchObject({
      reason: 'target_missing',
    });

    expect(
      await t.auth.membership.changeRole({ ...acting(admin, outsider), role: 'admin' }),
    ).toMatchObject({ reason: 'target_missing' });

    expect(canManage).not.toHaveBeenCalled();
  });

  it('names the action in canManage and in every refusal row', async () => {
    const canManage = vi.fn((_context: ManageContext) => false);
    const t = membershipApp({ canManage });
    const admin = await t.member('admin');
    const plain = await t.member('member');
    const outsider = await t.member(null);

    await t.auth.membership.remove(acting(admin, plain));
    await t.auth.membership.add({ ...acting(admin, outsider), role: 'member' });

    expect(canManage.mock.calls.map(([context]) => context)).toEqual([
      {
        actor: { scope: SCOPE, userId: admin.userId, role: 'admin' },
        action: 'remove',
        userId: plain.userId,
        from: 'member',
        to: undefined,
      },
      {
        actor: { scope: SCOPE, userId: admin.userId, role: 'admin' },
        action: 'add',
        userId: outsider.userId,
        from: undefined,
        to: 'member',
      },
    ]);

    const actions = () =>
      t.audit.events.filter((e) => e.type === 'membership.refused').map((e) => e.data?.['action']);

    expect(actions()).toEqual(['remove', 'add']);

    canManage.mockReturnValue(true);
    vi.spyOn(t.store, 'addMember').mockResolvedValueOnce(false);
    vi.spyOn(t.store, 'removeMember').mockResolvedValueOnce('stale');
    await t.auth.membership.add({ ...acting(admin, outsider), role: 'member' });
    await t.auth.membership.remove(acting(admin, plain));

    expect(actions()).toEqual(['remove', 'add', 'add', 'remove']);
  });
});

describe('membership guards fail closed', () => {
  it('refuses when the member lookup or canManage throws, and logs no membership data', async () => {
    const errors: Array<{ message: string; context: unknown }> = [];

    const logger = {
      debug: () => undefined,
      info: () => undefined,
      warn: () => undefined,
      error: (message: string, context?: unknown) => void errors.push({ message, context }),
    };

    let throwing = false;

    const t = membershipApp(
      {
        canManage: () => {
          if (throwing) throw new Error('policy service down');

          return true;
        },
      },
      { logger },
    );

    const admin = await t.member('admin');
    const target = await t.member('member');

    throwing = true;

    expect(
      await t.auth.membership.changeRole({ ...acting(admin, target), role: 'admin' }),
    ).toMatchObject({ code: 'forbidden', reason: 'check_failed' });

    throwing = false;
    vi.spyOn(t.store, 'findMember').mockRejectedValueOnce(new Error('database down'));

    expect(await t.auth.membership.remove(acting(admin, target))).toMatchObject({
      code: 'forbidden',
      reason: 'check_failed',
    });

    expect(errors).toHaveLength(2);

    expect(errors[0]).toMatchObject({
      message: 'Membership check failed',
      context: { action: 'change-role', userId: admin.userId },
    });

    expect(JSON.stringify(errors)).not.toContain('@example.com');
    expect((await t.store.findMember(SCOPE, target.userId))?.role).toBe('member');
  });

  it('refuses an actor who is not a member of the scope', async () => {
    const t = membershipApp();
    const elsewhere = await t.member('admin', 'org_2');
    const target = await t.member('member');

    expect(await t.auth.membership.remove(acting(elsewhere, target))).toMatchObject({
      code: 'forbidden',
      reason: 'actor_not_member',
    });
  });
});

describe('membership store conformance suite', () => {
  /** Checks and writes in two steps, with an await between: the race the suite must catch. */
  class RacyStore extends MemoryMembershipStore {
    override async changeRole(input: Parameters<MembershipStore['changeRole']>[0]) {
      const others = (await this.listMembers(input.scope)).filter(
        (m) => m.userId !== input.userId && input.adminRoles.includes(m.role),
      );

      await new Promise((resolve) => setTimeout(resolve, 1));

      if (others.length === 0 && !input.adminRoles.includes(input.to)) return 'last_admin';

      return super.changeRole({ ...input, adminRoles: [] });
    }
  }

  it('catches a store whose last-admin check is not atomic', async () => {
    const racing = membershipStoreConformance(new RacyStore()).find((c) =>
      c.name.startsWith('leaves one admin when two admins demote'),
    );

    await expect(racing?.run()).rejects.toThrow();
  });
});

describe('membership acting session', () => {
  it('refuses a session that is no longer live, or that belongs to someone else', async () => {
    const t = membershipApp();
    const admin = await t.member('admin');
    const target = await t.member('member');
    const other = await t.member('member');

    await t.auth.logout({ token: admin.token, meta: meta() });

    expect(await t.auth.membership.changeRole({ ...acting(admin, target), role: 'admin' })).toEqual(
      { ok: false, code: 'session_expired', reason: 'session_not_live' },
    );

    const fresh = await t.auth.login({ email: admin.email, password: PASSWORD, meta: meta() });

    if (!fresh.ok || fresh.value.kind !== 'session') throw new Error('login failed');

    const borrowed = { ...fresh.value.session.session, userId: other.userId };

    expect(
      await t.auth.membership.remove({ ...acting({ session: borrowed }, target) }),
    ).toMatchObject({ code: 'session_expired', reason: 'session_not_live' });

    expect((await t.store.findMember(SCOPE, target.userId))?.role).toBe('member');

    expect(t.audit.events.at(-1)).toMatchObject({
      type: 'membership.refused',
      reason: 'session_not_live',
      data: { action: 'remove' },
    });
  });
});

describe('membership revocation order', () => {
  it('signs the member out even when the store then refuses the change', async () => {
    const t = membershipApp({ revokeSessionsOnChange: true, canManage: () => true });
    const actor = await t.member('member');
    const soleAdmin = await t.member('admin');

    expect(await t.auth.membership.remove(acting(actor, soleAdmin))).toMatchObject({
      ok: false,
      code: 'last_admin',
    });

    expect((await t.store.findMember(SCOPE, soleAdmin.userId))?.role).toBe('admin');
    expect(await t.sessionOf(soleAdmin.token)).toBeNull();
  });

  it('writes nothing when the revocation before the write fails', async () => {
    const t = membershipApp({ revokeSessionsOnChange: true });
    const admin = await t.member('admin');
    const target = await t.member('member');

    vi.spyOn(t.auth.context, 'revokeAllSessions').mockRejectedValueOnce(new Error('redis down'));

    await expect(
      t.auth.membership.changeRole({ ...acting(admin, target), role: 'admin' }),
    ).rejects.toThrow('redis down');

    expect((await t.store.findMember(SCOPE, target.userId))?.role).toBe('member');
  });

  it('keeps the change and throws when the revocation after the write fails', async () => {
    const t = membershipApp({ revokeSessionsOnChange: true });
    const admin = await t.member('admin');
    const target = await t.member('member');
    const real = t.auth.context.revokeAllSessions.bind(t.auth.context);

    vi.spyOn(t.auth.context, 'revokeAllSessions')
      .mockImplementationOnce(real)
      .mockRejectedValueOnce(new Error('redis down'));

    await expect(t.auth.membership.remove(acting(admin, target))).rejects.toThrow('redis down');
    expect(await t.store.findMember(SCOPE, target.userId)).toBeNull();
    // The first bump already ended every session the member held before the change.
    expect(await t.sessionOf(target.token)).toBeNull();
  });
});
