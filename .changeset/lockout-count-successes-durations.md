---
'@noctcore/auth': minor
---

Two new lockout options, both off by default so nothing changes unless an app sets them.

`throttle.lockout.countSuccesses` (default `true`): when `false`, a correct password's slot in the account-wide budget (`perAccount`) comes back, so only failures count and a user who signs in many times within the window is no longer locked. The slot comes back when the sign-in completes (a session issued with `via: 'password'` or `via: 'second-factor'` and no `inherit`), not when the password proves right, so a correct password that opens a second-factor challenge keeps spending until the factor is proved. At `reauthenticate` and `changePassword` it comes back right after the correct password, since the caller already holds a session. A completion hands back at most one slot, and never more slots than correct passwords reserved in the window, however many sign-ins complete at once. `Throttle` gains `refundSuccess` and a `countSuccesses` field.

`throttle.lockout.durations`: a list of lock durations used in place of `baseLock` and `maxLock`. Lock N in a row lasts entry N and the last entry repeats, so `['15m', '1h']` locks for 15 minutes, then an hour each time after. The two-factor plugin's factor locks climb the same ladder. Startup refuses an empty list, an entry that is not a duration or is zero, and `durations` together with `baseLock` or `maxLock`.

The docs now say that `context.recordFailedProof` must be given only an account the request is already acting on, and that wrong codes while enrolling a factor or at a step-up count toward the permanent tier like wrong codes at login.
