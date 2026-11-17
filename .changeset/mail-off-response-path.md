---
'@noctcore/auth': minor
---

No flow awaits mail delivery any more. Sign-up, email verification (send and resend), password change, password reset, the reset request's job and the lockout notice from a password change call `mailer.send` and answer without awaiting the promise it returns, so a delivery that is slow, or never settles, no longer delays or hangs a response.

Timing changes for consumers: responses no longer include the time the promise from `send` takes to settle, and a reset job run by `auth.jobs.processPasswordReset` resolves before its mail is delivered. The call to `send` is still on the response path: whatever `send` does before it returns its promise (rendering a template, opening a connection) counts toward the response time, and sign-up sends different templates for a taken and a new address. `send` must only enqueue, with templates built in a worker.

Delivery from the library is at most once: each mail is handed over once, a `send` that throws or rejects is logged as `Mailer failed` and never retried, so retries belong to the app's queue. Enqueueing narrows the window in which mail can be lost but does not close it, because the enqueue itself is not awaited: a process that exits or a serverless instance frozen after the response can still lose it (no flush or `waitUntil` hook yet, #50). Background sends have no timeout or cap, so give the enqueue a timeout (#51).

Type break: `PluginContext.mail` now returns `void` instead of `Promise<void>`. Plugin code that calls `.then` on `ctx.mail(...)`, or returns it where a `Promise<void>` is expected, no longer type-checks. Code that only awaited it still compiles (lint may flag the await of a non-promise) and behaves the same, minus the wait.

The `afterRegister` hook stays awaited (an app may rely on its work being done before the answer), and its docs now say it runs only for a new address and so shows in sign-up timing: queue slow work instead of awaiting it. `registration.autoLogin` is documented as visible in sign-up timing too.
