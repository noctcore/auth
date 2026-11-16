---
'@noctcore/auth': minor
---

Add the store interfaces (users, sessions, one-time tokens, counters), the mail and audit event types, the `SessionManager` (opaque tokens stored as SHA-256, absolute and per-session idle expiry, touch that never resurrects, the epoch fence on mint and validate, eviction over a per-user cap), single-use link tokens and HMAC-stored numeric codes with an atomic attempt cap, and the throttle (fail-closed fixed windows; lockout budgets per account and IP and per account with backoff capped at 1 h and no permanent tier). `@noctcore/auth/testing` ships the runner-agnostic store conformance suite, in-memory stores that pass it, and test fakes.
