---
'@noctcore/auth': minor
---

No flow waits for the mailer any more. Sign-up, email verification (send and resend), password change, password reset, the reset request's job and the lockout notice from a password change hand each mail to `mailer.send` and answer without awaiting it, so a slow mailer, or one that never settles, no longer delays or hangs a response.

Timing changes for consumers: responses that used to include the mailer's send time no longer do, and a reset job run by `auth.jobs.processPasswordReset` resolves before its mail is delivered. Delivery from the library is at most once: each mail is handed over once, a `send` that throws or rejects is logged as `Mailer failed` and never retried, so retries belong to the app's mailer or queue. Keep `send` enqueueing rather than sending inline, so mail in flight is not lost when a process stops.

`PluginContext.mail` now returns `void` instead of `Promise<void>`: it hands the mail over and returns. Plugin code that awaited it still compiles and behaves the same, minus the wait.

The `afterRegister` hook stays awaited (an app may rely on its work being done before the answer), and its docs now say it runs only for a new address and so shows in sign-up timing: queue slow work instead of awaiting it. `registration.autoLogin` is documented as visible in sign-up timing too.
