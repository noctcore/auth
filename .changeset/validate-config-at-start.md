---
'@noctcore/auth': minor
---

`createAuth` now refuses, with an `AuthConfigError` that names the key, option values that used to boot and then quietly turn a check off: a boolean option that is not a real boolean, an attempt count or rate limit that is not a whole number of at least 1, and a zero window or lock duration. The plugins check their options the same way when they are created.

A `NaN` lockout limit from `Number(undefined)` meant the account never locked; a `NaN` `maxAttempts` meant wrong guesses never spent a code (only the door rate limits still applied); the string `"false"` for `registration.revealExisting` read as on, so sign-up answered `email_in_use` for taken addresses; a `NaN` `password.policy.minLength` accepted an empty password.

**Behaviour change:** a configuration that booted before can now throw at startup. Each value refused was already broken, but a deployment that passes one stops booting until it is fixed. Now refused:

- a string, number or other non-boolean for `registration.revealExisting`, `registration.autoLogin`, `passwordReset.markEmailVerified`, `session.cookie.secure`, `throttle.lockout.revealLocked` and `throttle.lockout.permanent.trustedDevices`, and in the plugins for invitations `recheckInviter` and membership `revokeSessionsOnChange` (where `"true"` used to read as off);
- a `NaN`, `Infinity`, fractional, zero, negative or non-number `emailVerification.maxAttempts`, `passwordReset.maxAttempts`, `emailChange.maxAttempts`, and `limit` under `throttle.lockout` (`perAccountIp`, `perAccount`, `perDevice`) or `throttle.doors`;
- a zero `window` under `throttle.lockout` or `throttle.doors`, a `throttle.doors` rule with a missing limit or a missing or unparsable window, and a zero `throttle.lockout.baseLock` or `maxLock`;
- a `password.policy.minLength` that is not a whole number (as well as below 8, as before), and a `password.policy.maxLength` that is not a whole number of at least `minLength`, `Infinity` included;
- twoFactor `trustedDevices: true` (or any value that is neither `false` nor an object), which untyped callers could pass and which turned trusted devices on with the defaults.

A key left out, `undefined` or `null` still gives its default, and a `null` door rule still falls back to the door's default. For `password.policy`, an `undefined` or `null` `minLength` or `maxLength` now keeps the default (12 and 256) instead of overwriting it; before, it disabled that bound. To fix a refused value, convert it first, for example `process.env.REVEAL_EXISTING === 'true'`, or a number with a fallback.
