/**
 * An in-memory MembershipStore with the guarantees the conformance suite asks
 * of real adapters: every guarded write reads and writes without an await in
 * the middle, so it is atomic on the event loop. For unit tests and prototypes
 * only.
 */
import type { MembershipStore, MemberWrite, StoredMember } from '../../ports/membership';

export class MemoryMembershipStore implements MembershipStore {
  /** scope -> userId -> role */
  private readonly scopes = new Map<string, Map<string, string>>();

  async findMember(scope: string, userId: string): Promise<StoredMember | null> {
    const role = this.scopes.get(scope)?.get(userId);

    return role === undefined ? null : { scope, userId, role };
  }

  async listMembers(scope: string): Promise<StoredMember[]> {
    return [...(this.scopes.get(scope) ?? [])].map(([userId, role]) => ({ scope, userId, role }));
  }

  async addMember(member: StoredMember): Promise<boolean> {
    const members = this.scopes.get(member.scope) ?? new Map<string, string>();

    if (members.has(member.userId)) return false;

    members.set(member.userId, member.role);
    this.scopes.set(member.scope, members);

    return true;
  }

  async changeRole(input: {
    scope: string;
    userId: string;
    from: string;
    to: string;
    adminRoles: readonly string[];
  }): Promise<MemberWrite> {
    const verdict = this.guard(input, !input.adminRoles.includes(input.to));

    if (verdict === 'done') this.scopes.get(input.scope)?.set(input.userId, input.to);

    return verdict;
  }

  async removeMember(input: {
    scope: string;
    userId: string;
    from: string;
    adminRoles: readonly string[];
  }): Promise<MemberWrite> {
    const verdict = this.guard(input, true);

    if (verdict === 'done') this.scopes.get(input.scope)?.delete(input.userId);

    return verdict;
  }

  /** Whether the write may happen; `losesAdmin` when the new state holds no admin role for the member. */
  private guard(
    input: { scope: string; userId: string; from: string; adminRoles: readonly string[] },
    losesAdmin: boolean,
  ): MemberWrite {
    const members = this.scopes.get(input.scope);
    const role = members?.get(input.userId);

    if (!members || role === undefined) return 'missing';
    if (role !== input.from) return 'stale';

    if (losesAdmin && input.adminRoles.includes(role)) {
      const others = [...members].some(
        ([userId, other]) => userId !== input.userId && input.adminRoles.includes(other),
      );

      if (!others) return 'last_admin';
    }

    return 'done';
  }
}
