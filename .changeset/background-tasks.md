---
'@noctcore/auth': minor
'@noctcore/auth-nestjs': minor
---

Background work (every mail, lock notices, and a password reset job run without `passwordReset.enqueue`) now goes through one runner, configured with the new optional `background` option of `createAuth`:

- `background.waitUntil(promise)` receives each task's promise as the task starts, so runtimes that freeze the instance after the response (Vercel, Cloudflare Workers) can keep mail sends alive. The promise never rejects.
- `auth.flush()` resolves once no background task is left that has neither settled nor timed out, tasks started while it waits included. Await it on graceful shutdown of a long-lived process, before closing your connections. `AuthModule` from `@noctcore/auth-nestjs` now does this in `beforeApplicationShutdown`.
- `background.timeout` stops waiting on a task that runs past it, so `flush` and `waitUntil` no longer wait for it. The task is logged as `Background task timed out: <label>`. A promise cannot be cancelled, so the task keeps running.
- `background.maxPending` refuses to start a new task while that many are still running, timed out or not. The dropped task is logged as `Background task dropped: <label>`, with the user id when there is one. This bounds memory when a mailer hangs instead of failing.

Timeouts and drops are counted on `metrics` as `auth_background_task` (exported as `BACKGROUND_METRIC`), with `task` and `outcome` labels. All three options are off by default, and behaviour without them is unchanged. One small exception: a detached reset job that throws is now logged as `Background task failed: password reset job` instead of `Detached password reset job failed`.

The library's own background work (the lock notice, and a reset job run without `enqueue`) now sends its mail inside its own task instead of starting a second one, so it takes one slot under `maxPending` and `flush` waits for the send. The lock notice also no longer waits for its audit write before sending the mail. A reset job run by your queue worker through `auth.jobs.processPasswordReset` still hands the mail to the mailer and returns, as before. Drops, timeouts and failures go to the configured `logger`, which is silent by default.
