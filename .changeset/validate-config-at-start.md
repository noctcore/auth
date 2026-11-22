---
'@noctcore/auth': patch
---

`createAuth` now refuses, with an `AuthConfigError` that names the key, option values that used to boot and then quietly turn a check off:

- a boolean option that is not `true` or `false`: `registration.revealExisting`, `registration.autoLogin`, `passwordReset.markEmailVerified`, `session.cookie.secure`, `throttle.lockout.revealLocked` and `throttle.lockout.permanent.trustedDevices`. The string `"false"` from an environment variable used to read as on, so `revealExisting: process.env.REVEAL_EXISTING` answered `email_in_use` for taken addresses although it was set to `"false"`;
- `emailVerification.maxAttempts`, `passwordReset.maxAttempts` and `emailChange.maxAttempts` that are not a whole number of at least 1. A `NaN` count never ran out, so wrong guesses never spent a code (only the door rate limits still applied);
- a `limit` under `throttle.lockout` (`perAccountIp`, `perAccount`, `perDevice`) or `throttle.doors` that is not a whole number of at least 1, and a zero `window` there. A `NaN` lockout limit from `Number(undefined)` meant the account never locked;
- a zero `throttle.lockout.baseLock` or `maxLock`, which made every lock end as it started;
- a `password.policy.minLength` that is not a whole number of at least 8 (a `NaN` minimum accepted an empty password), and a `password.policy.maxLength` that is not a whole number of at least `minLength` (a `NaN` or infinite maximum bounded nothing).

The plugins check their options the same way: `invitations` refuses a `recheckInviter` that is not `true` or `false`, `membership` a `revokeSessionsOnChange` that is not `true` or `false` (the string `"true"` used to read as off), and `twoFactor` a `trustedDevices` that is neither `false` nor an object (`true` or `"false"` used to turn devices on with the defaults).

A configuration that boots with real booleans and whole-number limits behaves exactly as before, and leaving a key out or passing `null` still gives its default. The values refused now were already broken, each one switching a protection off or making the option mean something other than what was written, which is why this ships as a patch: if startup now throws, convert the value first (for example `process.env.REVEAL_EXISTING === 'true'`, or a number with a fallback).
