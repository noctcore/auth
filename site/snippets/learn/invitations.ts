import type { InvitationsOptions } from '@noctcore/auth/invitations';

// The limits, written out. Pass them to invitations() beside store,
// authorize, onAccept and url, or leave them out for the same values.
export const invitationLimits = {
  // How long an invitation can be accepted; never more than 30 days.
  ttl: '7d',
  // Ask `authorize` again for the inviter when the invitation is accepted.
  recheckInviter: true,
  // Off: accepting needs a session of the account with the invited address.
  acceptWithoutSession: false,
  perInviter: { limit: 20, window: '1h' },
  // Across every scope, so a loop cannot flood one mailbox.
  perAddress: { limit: 3, window: '24h' },
  perIp: { limit: 10, window: '1m' },
} satisfies Partial<InvitationsOptions>;
