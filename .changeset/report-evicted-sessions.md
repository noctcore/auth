---
'@noctcore/auth': minor
'@noctcore/auth-redis': minor
---

Sessions evicted by the per-user cap (`session.maxPerUser`) are now reported exactly once, so apps can close their sockets and drop their caches.

- `IssuedSession` has a new `evicted` field: the ids of the user's older sessions that issuing this one deleted, oldest first, empty when none were. Every flow that returns an issued session (`login`, `register`, `reauthenticate`, `changePassword`, `sessions.revokeOthers`, email verification and change, the two-factor and invitation flows) carries it. `onSessionsRevoked` fires with reason `evicted` and the same ids, in the same form as every other reason; a hook that throws is logged and the sign-in still succeeds.
- Sign-ins racing at the cap no longer report one evicted session twice: only the sign-in whose delete removed it reports it.
- `SessionStore.delete` may now return the ids it removed (`Promise<void | readonly string[]>`). The memory and Redis stores do. A custom store that returns nothing keeps working, and the cap then reports every id it chose, as before. The store conformance suite checks the returned ids and the race at the cap when a store returns them.
