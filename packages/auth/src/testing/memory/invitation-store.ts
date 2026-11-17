/**
 * An in-memory InvitationStore with the guarantees the conformance suite asks
 * of real adapters: every check and write happens without an await in the
 * middle, so it is atomic on the event loop. For unit tests and prototypes only.
 */
import type { InvitationStore, StoredInvitation } from '../../ports/invitations';

export class MemoryInvitationStore implements InvitationStore {
  /** hash -> invitation */
  private readonly invitations = new Map<string, StoredInvitation>();

  async create(invitation: StoredInvitation, now: number): Promise<boolean> {
    for (const [hash, other] of this.invitations) {
      if (other.scope !== invitation.scope || other.email !== invitation.email) continue;
      if (other.expiresAt > now) return false;

      this.invitations.delete(hash);
    }

    this.invitations.set(invitation.hash, copy(invitation));

    return true;
  }

  async findByHash(hash: string): Promise<StoredInvitation | null> {
    const invitation = this.invitations.get(hash);

    return invitation ? copy(invitation) : null;
  }

  async consume(hash: string): Promise<StoredInvitation | null> {
    const invitation = this.invitations.get(hash);

    if (!invitation) return null;

    this.invitations.delete(hash);

    return copy(invitation);
  }

  async listByScope(scope: string, now: number): Promise<StoredInvitation[]> {
    return [...this.invitations.values()]
      .filter((i) => i.scope === scope && i.expiresAt > now)
      .map(copy);
  }

  async revoke(scope: string, id: string): Promise<boolean> {
    for (const [hash, invitation] of this.invitations) {
      if (invitation.scope === scope && invitation.id === id) return this.invitations.delete(hash);
    }

    return false;
  }

  async deleteByInviter(inviterId: string, scope?: string): Promise<void> {
    for (const [hash, invitation] of this.invitations) {
      if (invitation.inviterId === inviterId && (scope === undefined || invitation.scope === scope))
        this.invitations.delete(hash);
    }
  }
}

function copy(invitation: StoredInvitation): StoredInvitation {
  return { ...invitation, payload: { ...invitation.payload } };
}
