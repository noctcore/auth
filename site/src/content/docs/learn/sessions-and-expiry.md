---
title: Sessions and expiry
description: Opaque tokens, hashed storage, absolute and idle expiry, and why a revoked session stays dead.
---

## What goes wrong

A session is a bearer credential: whoever holds the value is the user. Two things make that dangerous. If the server stores the value itself, a leaked store (a database dump, a Redis snapshot, a backup) hands the attacker every live session. And if sessions never expire, one stolen cookie works forever.

## The rule

**The token is opaque and random.** The cookie carries 32 bytes from a cryptographically secure random source. It encodes nothing: no user id, no expiry, nothing to forge or parse.

**The store keeps only the hash.** The store key is the SHA-256 of the token, never the token. A leaked store cannot be replayed, because the attacker holds hashes and needs the preimage. SHA-256 is enough here (no slow password hash) because the input already has 256 bits of entropy, so there is nothing to brute force.

**Two expiries, for two threats.**

- *Absolute expiry* is the store's TTL on the session record. However active the user is, the session ends when the TTL does. This bounds the damage of a stolen cookie.
- *Idle expiry* is per session: if the user has not been seen for the idle window, the session is rejected. This ends sessions left open on a shared machine.

**Refreshing last-active without resurrecting.** Validating a session would otherwise write on every request. Instead, the stored last-active time is refreshed at most once per interval. The write is update-only-if-exists and keeps the record's remaining TTL. That detail matters: a plain "set" could recreate a record that was revoked a moment earlier, between the read and the write. Update-only-if-exists means a revoked session can never be resurrected by a late refresh, and keeping the TTL means a refresh never extends the absolute expiry.

## Where the package and the guide differ

- **Token shape.** The guide recommends a session id plus a separate secret, so the session can be referenced without exposing a credential. The package keeps a single random token and uses its SHA-256 as the store key, which keeps sessions issued by the existing apps valid on adoption. The id an app lists or revokes is that hash, which is not a credential.
- **Refresh interval.** The guide suggests refreshing the expiry hourly or daily. The package refreshes last-active at most once a minute, because the default idle timeout is 30 minutes; the refresh never moves the absolute expiry.
- **Sign-out on password change.** The guide leaves it to the user. The package always revokes every session and re-issues the current one.
- **Revoking sessions.** As the guide asks, revoking another device's session, or every other session at once, needs a fresh credential proof (within 10 minutes), so a stolen session cannot sign the owner out. Signing out of the current device needs none.

## Further reading

[Sessions](https://auth.pilcrowonpaper.com/sessions) and [Auth sessions](https://auth.pilcrowonpaper.com/auth-sessions) in Pilcrow's auth guide.

## Related

[Revocation races and the epoch fence](/auth/learn/revocation-races/) covers how revoking every session of a user stays correct while a login is in flight.
