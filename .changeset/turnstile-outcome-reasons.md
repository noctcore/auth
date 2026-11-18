---
'@noctcore/auth': minor
---

`turnstile()` now says why. The verifier it returns gains `check(token, context)`, which verifies exactly like `verify` and returns the verdict with its cause, and the new `onResult` option is called with that outcome for every verification (pass, reject and unavailable), so an operator can log or count outages apart from misconfigurations. An outcome holds `verdict`, `door`, the `errorCodes` siteverify answered with, and a `reason`: for `unavailable`, one of `timeout`, `network-error`, `http-status` (with the `status` code), `unparsable-body` or `provider-error` (Cloudflare's `internal-error`); for `reject`, one of `missing-token`, `token-too-long`, `provider-refused`, `hostname-mismatch` or `action-mismatch`. Outcomes never carry the token or the secret. The hook is not awaited and cannot change the verdict (the outcome is frozen); a hook that throws or rejects is reported to the new `logger` option (silent by default) with its message only; if that log call throws too, or the thrown value cannot be turned into text, the failure is dropped and the verdict still stands. Keep a synchronous hook cheap: it still runs on the request path.

`describeError`, used for every error the package logs, no longer throws on a value without a usable `toString` (it logs `unprintable error` instead).

Additive: `verify` answers as before, an outage still refuses the request, and the `unavailable` reasons are a shared `UnavailableReason` type (with `UnavailableOutcome` and `OutcomeHook`) for other provider checks to reuse.
