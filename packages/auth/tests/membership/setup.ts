// Shared setup for the membership tests: an app with the plugin on in-memory
// stores, and a scope with signed-in members.
import type { StoredSession } from '../../src';
import { membership, type MembershipOptions } from '../../src/plugins/membership';
import { MemoryMembershipStore } from '../../src/testing';
import { meta, setup } from '../flows/setup';

export { meta, PASSWORD } from '../flows/setup';

export const SCOPE = 'org_1';

type Session = StoredSession<Record<string, never>>;

/** An app with the membership plugin; `owner` and `admin` are the admin roles. */
export function membershipApp(
  plugin: Partial<MembershipOptions> = {},
  overrides: Parameters<typeof setup>[0] = {},
) {
  const store = new MemoryMembershipStore();
  const plugged = membership({ store, adminRoles: ['owner', 'admin'], ...plugin });
  const env = setup({ ...overrides, plugins: [plugged, ...(overrides.plugins ?? [])] });

  const auth = env.auth as typeof env.auth & {
    membership: ReturnType<NonNullable<typeof plugged.flows>>;
  };

  let count = 0;

  /** A signed-in user who holds `role` in `scope` (or no membership when `role` is null). */
  async function member(role: string | null, scope = SCOPE) {
    count++;

    const email = `user${count}@example.com`;
    const { token, session } = await env.signedInUser(email);

    if (role !== null) await store.addMember({ scope, userId: session.userId, role });

    return { token, session: session as Session, userId: session.userId, email };
  }

  return { ...env, auth, store, member };
}

export type MembershipApp = ReturnType<typeof membershipApp>;

/** The input every flow takes, acting as `actor` on `target`. */
export function acting(actor: { session: Session }, target: { userId: string }, scope = SCOPE) {
  return { session: actor.session, scope, userId: target.userId, meta: meta() };
}
