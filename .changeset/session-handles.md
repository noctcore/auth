---
'@noctcore/auth': minor
'@noctcore/auth-trpc': minor
---

`sessions.list` no longer returns the session's store key. Each entry now carries a public `handle` in place of `id`: an HMAC-SHA-256 of the store key under a key derived from the server secret, as 43 characters of unpadded base64url, so a page that shows the list (or anything that reads it) never learns a store key, and a leaked store cannot be matched against handles without the secret. `sessions.revoke` takes `{ session, handle, meta }` and looks the handle up among the caller's own live sessions only; a handle it does not find (garbage, a raw store key, a gone session or another user's) answers `{ revoked: false }`, always the same. Another device still needs a fresh password proof, asked before any lookup.

`onSessionsRevoked` now also receives `sessionHandles`, the same sessions' handles in the order of `sessionIds`, for every reason (`evicted` included), so apps can match revocations against the list. The new `auth.sessions.handle(sessionId)` (and `sessionHandle` on the plugin context) maps a store key you hold on the server to its handle. Rotating the server secret changes every handle; sessions survive it.

`@noctcore/auth-trpc`: `sessionSummaryOutput` has `handle` in place of `id` and strips a store key a procedure returns, and `revokeSessionInput` is `{ handle }`.

Migration (a breaking change to a public shape): rename `id` to `handle` in your session list and revoke routes and in any client code, and drop session ids a client stored, since revoke no longer accepts a store key: list again and use the handles it returns. See "Session handles" on the Sessions and expiry page.
