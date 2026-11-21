---
'@noctcore/auth': minor
---

A new `previousSecret` option keeps the secret a rotation replaced (or several, newest first) for a grace window, so rotating `secret` no longer voids every pending code, trusted-device cookie, session handle and two-factor recovery code at once. Without it, behaviour is unchanged.

- Every key is derived from each secret. Signing, keyed hashing for storage and new cookies use only the current secret; verification tries the current key, then each previous one, in constant time per candidate. A code from before the rotation is still found and counts one attempt per try, a device cookie from before still lets a correct password through a lock (and the next sign-in writes a new one), a handle from before still revokes its session (the next list shows the new one), and a recovery code from before is still spent once. Invitations stored under the keyed hash used before 0.6 are found under a previous secret too.
- Startup fails with `AuthConfigError` when a previous secret equals `secret` or another previous one, or is shorter than 32 bytes.
- Plugin context: new `keyedHashes(purpose, message)` (the keyed hash under each secret, current first) and `matchesSessionHandle(sessionId, handle)`.
- Remove `previousSecret` once the longest-lived value has expired: the trusted-device max age (30 days by default). Recovery codes never expire, so ask users to make a new set before removing it. The README walks through the procedure.
