---
'@noctcore/auth': minor
'@noctcore/auth-trpc': minor
---

Add two opt-in lockout options, both off by default, so the default lockout (a capped temporary lock answered like a wrong password) is unchanged.

- `throttle.lockout.permanent: { afterLocks, trustedDevices? }`: after `afterLocks` temporary locks in a row (a successful sign-in resets the count), the next lock holds until an admin lifts it with the new `auth.lockout.clear({ email | userId, meta })`; `auth.lockout.inspect` reads the state. A password reset does not lift it. The lock is kept under the user id, so it follows the account through an email change; a lock on an address with no account is cleared when someone signs up on it. A permanent lock ends the account's sessions (`onSessionsRevoked` hears `locked-permanently`), writes an `account.locked_permanently` audit row, mails the owner a `lockout` mail with `permanent: true`, and runs the new `onPermanentLock` hook. With `trustedDevices` (the default) the owner's device cookie still gets through and no session may change the email; with `trustedDevices: false` every session and device cookie ends and every session door is refused until the clear. Trade-off: anyone who knows an address can lock its owner out on purpose, so pair it with a captcha and per-IP rate limits.
- `throttle.lockout.revealLocked`: login answers the new public code `account_locked` (with `retryAfterSeconds` for a temporary lock) instead of `invalid_credentials` while the address is locked. Trade-off: the answer tells anyone that the address is locked and when it lifts, an enumeration signal the generic answer does not give.

`AuthErrorCode` gains `account_locked`; code that switches exhaustively over it needs a case. `@noctcore/auth-trpc` maps it to `FORBIDDEN`. The counter store conformance suite gains a case for the far-future expiry the permanent tier stores its marker with.
