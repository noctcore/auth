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

**A cap per user, and word of what it ends.** A user holds at most `session.maxPerUser` sessions (10 by default). Issuing one more evicts the oldest, after the new session is written, so sign-ins racing at the cap still end up within it. An evicted session is gone like a revoked one, but whatever the app holds for it (an open socket, a cache entry) is not, so the library names it: the issued session carries the ids in `evicted`, and `onSessionsRevoked` fires with reason `evicted` and the same ids. Each eviction is reported once: when two racing sign-ins both pick the same oldest session, only the one whose delete removed it reports it.

## Session handles

A "where you're signed in" page needs a name for each session, so the user can sign one out. The store key would do, but it is the storage identity of a bearer secret: anything that reads the page (a script injected into it, a browser extension, a shared screen, a client log) would learn the key of every session on the account, and could match those keys against a leaked session store.

So `auth.sessions.list(session)` names each session by a **handle** instead: an HMAC-SHA-256 of the store key under a key derived from the server secret, as 43 characters of unpadded base64url. A plain hash of the key would hide it too, but anyone holding a leaked store could compute it and match the two; the HMAC needs the secret as well. The handle never has the 64-character hex shape of a store key, so the two cannot be mixed up.

- **Revoking by handle.** `auth.sessions.revoke({ session, handle, meta })` looks the handle up among the caller's own live sessions only. A handle it does not find (garbage, a raw store key, a session already gone, or another user's session) answers `{ revoked: false }`, every time the same, so revoke cannot tell anyone whether a handle belongs to someone. Revoking another device still needs a fresh password proof, asked before any lookup.
- **The current session** is the entry with `current: true`. Signing it out is better done with `logout`, which also clears the cookie.
- **Correlating server-side.** `onSessionsRevoked` receives `sessionHandles` beside `sessionIds`, in the same order, so a socket server or a client cache keyed by handle can drop the right entries, whatever the reason (`revoke-one`, `evicted`, `password-change` and the rest). `auth.sessions.handle(session.id)` gives the handle of any session id you hold on the server.
- **Rotating the server secret** changes every handle (sessions themselves survive it). A client holding an old handle gets `{ revoked: false }` and lists again.

### Upgrading to handles

Up to `@noctcore/auth` 0.5 the list returned the store key as `id`, and revoke took it as `id`. Both are now `handle`, and a store key is no longer accepted by revoke: it answers `{ revoked: false }`, like any handle it does not know. Rename the field in your list and revoke routes (and in `revokeSessionInput` and `sessionSummaryOutput` with the tRPC adapter), and drop any session ids a client kept: list again and use the handles it returns. Code that kept store keys on the server, from `session.id` or the hook's `sessionIds`, can map them with `auth.sessions.handle(id)`.

## Where the package and the guide differ

- **Token shape.** The guide recommends a session id plus a separate secret, so the session can be referenced without exposing a credential. The package keeps a single random token and uses its SHA-256 as the store key, which keeps sessions issued by the existing apps valid on adoption. That key never goes to a client: what an app lists and revokes is a separate handle, below.
- **Refresh interval.** The guide suggests refreshing the expiry hourly or daily. The package refreshes last-active at most once a minute, because the default idle timeout is 30 minutes; the refresh never moves the absolute expiry.
- **Sign-out on password change.** The guide leaves it to the user. The package always revokes every session and re-issues the current one.
- **Revoking sessions.** As the guide asks, revoking another device's session, or every other session at once, needs a fresh credential proof (within 10 minutes), so a stolen session cannot sign the owner out. Signing out of the current device needs none.

## Further reading

[Sessions](https://auth.pilcrowonpaper.com/sessions) and [Auth sessions](https://auth.pilcrowonpaper.com/auth-sessions) in Pilcrow's auth guide.

## Related

[Revocation races and the epoch fence](/auth/learn/revocation-races/) covers how revoking every session of a user stays correct while a login is in flight.
