---
'@noctcore/auth': minor
---

Two new lockout options, both off by default so nothing changes unless an app sets them.

`throttle.lockout.countSuccesses` (default `true`): when `false`, a correct password's slot in the account-wide budget (`perAccount`) comes back, so only failures count and a user who signs in many times within the window is no longer locked. The slot comes back when the sign-in completes (a session issued with `via: 'password'` or `via: 'second-factor'` and no `inherit`), not when the password proves right, so a correct password that opens a second-factor challenge keeps spending until the factor is proved. At `reauthenticate` and `changePassword` it comes back right after the correct password, since the caller already holds a session. A completion hands back at most one slot, and never more slots than correct passwords reserved in the current account-wide window, however many sign-ins complete at once. Refunds are matched by count, not to the attempt that earned them: a completion that reserved nothing of its own (a challenge opened in an earlier window, a device sign-in) can take a slot another correct password in the window is owed. Slots owed in a window that ended, including one a lock ended, never come back in the next. `Throttle` gains `refundSuccess` and a `countSuccesses` field.

`throttle.lockout.durations`: a list of lock durations used in place of `baseLock` and `maxLock`. Lock N in a row lasts entry N and the last entry repeats, so `['15m', '1h']` locks for 15 minutes, then an hour each time after. The two-factor plugin's factor locks climb the same ladder. Startup refuses an empty list, an entry that is not a duration or is zero, and `durations` together with `baseLock` or `maxLock`.

With `revealLocked`, a lock that a racing request set and that can no longer be read is answered as one of the first lock's length: the first `durations` entry, or `baseLock` capped at `maxLock`. Before, it was `baseLock` uncapped, so the answer changes only for an app whose `baseLock` is longer than its `maxLock`, where it now matches the lock actually set. Such a configuration is still accepted (every lock is capped at `maxLock`), since refusing it at startup would stop apps that boot today.

The docs now say that `context.recordFailedProof` must be given only an account the request is already acting on, and that wrong codes while enrolling a factor or at a step-up count toward the permanent tier like wrong codes at login.
