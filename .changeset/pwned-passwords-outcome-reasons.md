---
'@noctcore/auth': minor
---

`pwnedPasswords()` now says why it returned `unavailable`. The checker it returns gains `check(password)`, which checks exactly like calling it and returns the verdict with its cause, and the new `onResult` option is called with that outcome for every check (clean, breached and unavailable), so an operator can log or count a timeout apart from a changed response format. An `unavailable` outcome holds a `reason`: `timeout`, `network-error`, `http-status` (with the `status` code) or `unparsable-body`. Outcomes never carry the password, its hash or the hash prefix. The hook is not awaited and cannot change the verdict (the outcome is frozen); a hook that throws or rejects is reported to the new `logger` option (silent by default) with its message only.

Additive: the function still answers `clean`, `breached` or `unavailable`, a custom `breachCheck` function keeps working, and an outage still accepts the password unchecked.
