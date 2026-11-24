---
'@noctcore/auth': minor
---

New session option `session.requireFreshAuth: { revokeSession?: boolean; revokeOtherSessions?: boolean }`, both `true` by default, so nothing changes unless an app sets it. With `revokeSession: false`, `sessions.revoke` ends another device's session without a credential proof inside `freshAuthAge`; with `revokeOtherSessions: false`, `sessions.revokeOthers` signs out every other device without one. The door still needs a live session of the same user (`session_expired` otherwise), and `freshAuthAge` and every other door (the email change, two-factor enrollment and management, step-up) keep their check. Startup refuses a `requireFreshAuth` that is not an object, and a value under it that is not `true` or `false`.

`sessions.revoke` now answers `{ revoked: true, sessionId }` for a session it ended, where `sessionId` is the session's store key, the same id `onSessionsRevoked` reports, so an app can close that session's live connections right after the call. A handle that names no session of the caller still answers `{ revoked: false }`, with no id. The store key is for the server only: if your route sends `result.value` to the client as it is, send `{ revoked: result.value.revoked }` instead, as the examples now do. The tRPC adapter's `revokedOutput` already strips the id. The new type `RevokeSessionOutcome` names the answer.
