---
'@noctcore/auth': minor
'@noctcore/auth-redis': minor
---

Sessions evicted by the per-user cap (`session.maxPerUser`) are now reported exactly once, so apps can close their sockets and drop their caches.

- `IssuedSession` has a new `evicted` field: the ids of the user's older sessions that issuing this one deleted, oldest first, empty when none were. Every flow that returns an issued session (`login`, `register`, `reauthenticate`, `changePassword`, `sessions.revokeOthers`, email verification and change, the two-factor and invitation flows) carries it. `onSessionsRevoked` fires with reason `evicted` and the same ids, in the same form as every other reason; a hook that throws is logged and the sign-in still succeeds.
- Sign-ins racing at the cap no longer report one evicted session twice, and an eviction racing a sign-out or a revocation of the same session reports it under one reason only: the call whose delete removed a session reports it. `logout`, `sessions.revoke`, `sessions.revokeAll`, revoke-others and the other revoke-all reasons now report (to the hook and in their answer) only the sessions their own delete removed. `onSessionsRevoked` is awaited on the sign-in that evicts: keep it fast.
- `SessionStore.delete` may now return the ids it removed (`Promise<void | readonly string[]>`). The memory and Redis stores do. A custom store that returns nothing keeps working, and the cap then reports every id it chose, as before. A store whose `delete` returns something else (a count, say) is treated the same way. The store conformance suite has three new cases for the returned ids and the races; a store whose `delete` returns nothing fails them with a message, or passes `deleteReportsRemoved: false` to list them as skipped.
