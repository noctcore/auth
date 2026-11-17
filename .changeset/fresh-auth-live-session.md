---
'@noctcore/auth': minor
---

Every door that needs fresh authentication now reads it from the live session in the store, not from the session object the caller passes: revoking another device (`sessions.revoke`), starting and confirming a second-factor enrollment, and the two-factor `requireStepUp` check. `sessions.revokeOthers` already did this. A hand-built or copied session object claiming a recent `authenticatedAt` is refused with `fresh_auth_required`.

Plugins get the same check as `context.requireFreshLiveSession(session)`. It answers `session_expired` unless the session is live and still the same user's, then `fresh_auth_required` as `requireFreshAuth` does, and returns the live copy.

Behaviour change: at these doors, a session that has expired, gone idle, been revoked or been rotated away now gets `session_expired` instead of being judged on the object passed in. For example, `requireStepUp` on a session replaced by `reauthenticate` used to pass on the old object's proof.
