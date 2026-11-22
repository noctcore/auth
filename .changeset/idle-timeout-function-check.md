---
'@noctcore/auth': minor
---

An `idleTimeout` function's value is now checked against `session.touchInterval` at each sign-in, by the same rule that stops the boot for a fixed value. Before, the startup check skipped a function and the mint stored whatever it returned, so `idleTimeout: () => '10m'` with `touchInterval: '15m'` issued sessions that were never touched under steady use and were refused as `idle` ten minutes after sign-in while the user was active.

**Behaviour change:** a sign-in for which the `idleTimeout` function returns a value no longer than `touchInterval` now throws an `AuthConfigError` before any session is written, instead of issuing a session that expires while in use. Sessions whose value is longer still mint as before. To fix it, shorten `touchInterval` or raise the function's shortest value above it.
