---
'@noctcore/auth': minor
'@noctcore/auth-prisma': patch
---

Invitations now survive a rotation of the server secret, and can opt into accepting without a session.

- Invitation tokens are stored as a plain SHA-256 instead of an HMAC under a key derived from `secret`, like the reset and verification links (the token is 256 random bits, so a leaked table still holds no usable link). Rotating `secret` no longer voids pending invitations. Invitations created before this release are still found under their old hash until they expire (30 days at most), but a rotation still voids those. No migration is needed; the `AuthInvitation` model is unchanged (only its comment in `auth.prisma` is updated).
- New option `acceptWithoutSession` (default `false`): `accept` then also takes `session: null`, and the token joins the account that holds the invited address. That address must be verified (an unverified account is refused and nothing is spent), the inviter is checked again, and no session is issued, so nobody is signed in by the link and no second factor is skipped. With the option off, `session: null` is refused with `forbidden` before the token is looked up. Anything but `true` or `false` is refused at startup. The accepted audit row carries `withoutSession: true`.
- Rolling back: invitations created on this release are stored under the new hash, which 0.5 does not look up, so after a rollback to 0.5 they answer `invalid_token` and must be revoked and sent again. Invitations created on 0.5 keep working in both directions.
- The docs now cover moving an account from one scope to another through an invitation: accepting into an account that belongs elsewhere is allowed, and `onAccept` decides whether it adds a seat or moves the account.
