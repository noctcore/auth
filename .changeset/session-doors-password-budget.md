---
'@noctcore/auth': patch
---

`reauthenticate` and `changePassword` now spend login's lockout budgets before they check the current password, through the same gate and counters: the per (account, IP) and account-wide budgets while the account is unlocked, so guesses through login and both doors add up, and under a lock the trusted devices' shared budget, the live session counting as one more device. A stolen session that is alive but not fresh no longer gets about 30 checked guesses per 15 minutes while login answers locked; it gets no more than a stolen device cookie would at login. The owner can still step up under a lock someone else set. A refused attempt answers `invalid_credentials` (or `account_locked` with `revealLocked`), like login, after the same password check. Callers that prove the right password within the budgets see no change.
