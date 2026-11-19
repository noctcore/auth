---
'@noctcore/auth': patch
---

Imported recovery codes (`importedRecoveryCodes` on the two-factor plugin) are rotated more carefully at login. The `recovery-code-used` mail and the audit row's `remaining` now count the new set (10) when the login replaced it, instead of the old codes that were just voided; a step-up or password change still reports the old count. Of two logins at once with two different imported codes, only one replaces the set and shows it, and the other gets its session with `recoveryCodes: null`, so no shown set is dead. A failure while replacing the set (the store is down) no longer leaves a session without a cookie: the session is returned with `recoveryCodes: null` and the failure is logged. The option's docs now say that the hash also runs with `NO_SUCH_USER_ID` on refused paths, and that a throwing hash can be recorded as `malformed_recovery_code`.
