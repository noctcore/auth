---
'@noctcore/auth': minor
---

Add the invitations plugin, `@noctcore/auth/invitations`, with flows under `auth.invitations` (`create`, `list`, `revoke`, `accept`, `register`). Tokens are 256 random bits, stored only as a keyed hash, single use (spent atomically by the store), bound to the invited address and expiring after 7 days by default (at most 30). `accept` needs a session whose verified address is the invited one and issues no session; `register` creates an account only for an address that has none, marks it verified and issues its session through `issueSession` with `via: 'invitation'`, so the two-factor plugin still applies. The plugin refuses to start without `authorize`, asks it on every create, list and revoke and again for the inviter on accept, deletes an inviter's pending invitations when all their sessions are revoked, keeps one live invitation per scope and address, and limits creates per address, per inviter and per IP. `create` never reads the invited address from the user store.

- New store port `InvitationStore`, with `invitationStoreConformance` and `MemoryInvitationStore` in `@noctcore/auth/testing`.
- New mail event `invitation`, the first without a `userId`. A mailer that switches over every type with a `never` check needs a case for it.
- New audit event types `invitation.created`, `invitation.deduplicated`, `invitation.revoked`, `invitation.accepted` and `invitation.refused`. An audit sink that switches over every type with a `never` check needs cases for them.
