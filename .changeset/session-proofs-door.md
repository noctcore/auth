---
'@noctcore/auth': minor
---

New lockout option `throttle.lockout.sessionProofs: 'lockout' | 'door'`, default `'lockout'`, so nothing changes unless an app sets it.

By default `reauthenticate` and `changePassword` prove the current password through login's lockout: a wrong one spends the account's sign-in budget, can lock the account, sends the lock mail and counts toward the permanent tier, and a correct one under a lock needs a free device slot. So whoever holds a session, a stolen one included, can lock the owner out of sign-in by guessing wrong current passwords.

With `'door'`, each door's own per-user limit (`throttle.doors`, `password-change` and `reauthenticate`, 5 per 5 minutes by default) is the only budget. A wrong password writes `password.change_failed` and touches no lockout counter (no lock, no lock mail, nothing toward the permanent tier), and a temporary lock does not refuse a correct password from a live session. The permanent tier refuses these doors as before, which is only with `permanent.trustedDevices: false`. The trade-off: guesses from a stolen session then run at the door's rate and never lock anything, so keep the door limits tight. `Throttle` gains a `sessionProofs` field, and startup refuses any other value.
