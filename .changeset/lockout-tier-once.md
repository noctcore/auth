---
'@noctcore/auth': patch
---

The lockout backoff now rises one step per lock, not one step per request that crosses the limit. A large parallel burst could cross the account-wide limit several times before the lock was visible, and each crossing raised the tier, so the next lock jumped straight to the cap. Only the request whose increment creates the lock now raises the tier and reports `newLock`; a crossing that finds the lock already running (a burst, or a wrong password let through by a device cookie) still counts, but leaves the tier and the lock's end alone and sends no second lock notice. No more guesses get through than before. The same holds for the second-factor lock.

Signing out every other device (`auth.sessions.revokeOthers`) now checks fresh authentication on the session it reads live from the store, not on the object the caller passed in.
