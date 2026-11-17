---
'@noctcore/auth': minor
'@noctcore/auth-nestjs': minor
---

Background work (every mail, lock notices, and a password reset job run without `passwordReset.enqueue`) now goes through one runner, configured with the new optional `background` option of `createAuth`:

- `background.waitUntil(promise)` receives each task's promise as the task starts, so runtimes that freeze the instance after the response (Vercel, Cloudflare Workers) can keep mail sends alive. The promise never rejects.
- `auth.flush()` resolves once no background task is left that has neither settled nor timed out, tasks started while it waits included. Await it on graceful shutdown of a long-lived process, before closing your connections. Pass `{ timeout }` to give up after that long; whatever is still running is logged as `Background flush stopped waiting` and left running. `AuthModule` from `@noctcore/auth-nestjs` now does this in `beforeApplicationShutdown`, bounded by its new `shutdownTimeout` option (default `'10s'`), so a mailer that never settles cannot hang `app.close()` or SIGTERM.
- `background.timeout` stops waiting on a task that runs past it, so `flush` and `waitUntil` no longer wait for it. The task is logged as `Background task timed out: <label>`. A promise cannot be cancelled, so the task keeps running.
- `background.maxPending` refuses to start a new task while that many are still running, timed out or not. The dropped task is logged as `Background task dropped: <label>`, with the user id when there is one. This bounds memory when a mailer hangs instead of failing.

Timeouts and drops are counted on `metrics` as `auth_background_task` (exported as `BACKGROUND_METRIC`), with `task` and `outcome` labels. All three options are off by default, and behaviour without them is unchanged. One small exception: a detached reset job that throws is now logged as `Background task failed: password reset job` instead of `Detached password reset job failed`.

Task labels, as they appear in these logs and in the `task` label of the metric:

- `mail <type>` (such as `mail lockout` or `mail password-reset`): one per mail, capped.
- `verification mail`: a sign-up's verification code and mail, capped.
- `audit <type>`: the `register.created` and `account.locked` rows, uncapped.
- `existing address notice`: the owner lookup and the `register.existing` row of a sign-up with a taken address, uncapped; its mail is a `mail account-exists` task.
- `password reset job`: a reset job run without `enqueue`, uncapped; its mail is a `mail password-reset` or `mail password-reset-code` task.

The `lockout notice` label is gone: a lock notice is now an `audit account.locked` task plus a `mail lockout` task, so the mail no longer waits for the audit write, and a failure that was logged as `Background task failed: lockout notice` is now logged under one of those two labels (a failed send still as `Mailer failed`). Update any alert that matches the old label. A reset job run by your queue worker through `auth.jobs.processPasswordReset` hands the mail to the mailer and returns, as before. Drops, timeouts and failures go to the configured `logger`, which is silent by default.

Under `maxPending` only mail is dropped, plus the `email.verification_sent` row of a dropped verification mail (a dropped mail was not sent). Every other audit row written off the response path (`register.created`, `register.existing`, `account.locked`, `password.reset_request_ignored`) is in a task the cap never drops and never counts. Those tasks take no slots, so a hung audit sink, or a user store that hangs during the lookup of a taken-address sign-up or a detached reset job, still grows memory as before.
