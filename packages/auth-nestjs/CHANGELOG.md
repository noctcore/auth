# @noctcore/auth-nestjs

## 0.5.0

### Minor Changes

- [#67](https://github.com/noctcore/auth/pull/67) [`fb9f5d8`](https://github.com/noctcore/auth/commit/fb9f5d80dcdc515ff0e09b453c18136adddbd6ca) Thanks [@Shironex](https://github.com/Shironex)! - Background work (every mail, lock notices, and a password reset job run without `passwordReset.enqueue`) now goes through one runner, configured with the new optional `background` option of `createAuth`:
  
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

### Patch Changes

- Updated dependencies [[`fb9f5d8`](https://github.com/noctcore/auth/commit/fb9f5d80dcdc515ff0e09b453c18136adddbd6ca), [`76717de`](https://github.com/noctcore/auth/commit/76717de578fbd4f83973dcf544acafeb1d5c9dad), [`5b79f16`](https://github.com/noctcore/auth/commit/5b79f16f9a597db92131f6684114c9f872cac4f5), [`c09f611`](https://github.com/noctcore/auth/commit/c09f611bc86253f33220e6d6ace54743de5cc1af), [`57440a0`](https://github.com/noctcore/auth/commit/57440a046b8f63cbca56f273ac611a8d6d391ebb), [`2ab09b7`](https://github.com/noctcore/auth/commit/2ab09b7b3769e14fbd72259138592df55a8bb3bb), [`e73f7a0`](https://github.com/noctcore/auth/commit/e73f7a0096808eb2fa9f705fe6c32983fb752e08)]:
  - @noctcore/auth@0.5.0

## 0.4.0

### Patch Changes

- Updated dependencies [[`a78168e`](https://github.com/noctcore/auth/commit/a78168e668f7add8256d44596bd29a6455f61dd1)]:
  - @noctcore/auth@0.4.0

## 0.3.0

### Minor Changes

- [#52](https://github.com/noctcore/auth/pull/52) [`291ebee`](https://github.com/noctcore/auth/commit/291ebeebe7a0a0a717efe88de8dfd9071d65cebf) Thanks [@Shironex](https://github.com/Shironex)! - Add `@noctcore/auth-nestjs`, the NestJS module: `AuthModule.forRoot` and `forRootAsync` provide the `createAuth` result under `AUTH`, register `SessionGuard` globally (closed by default, `@Public()` opens a route) and run `CsrfMiddleware` before every route (Origin allowlist, `Sec-Fetch-Site`, and a signed double-submit token bound to the session or a pre-session id; a refusal is a 403 with a fixed body). `@CurrentUser()`, `@CurrentSession()` and `@AuthMeta()` read what the guard resolved; `@RequireRole()` reads roles fresh on every request and `@RequireFreshAuth(maxAge?)` can only shorten `freshAuthAge`. `SessionCookies` writes a new or ended session with its CSRF token. `trustedHopsFromEnv` and `configureTrustProxy` count proxy hops from the right and refuse to start in production without `TRUST_PROXY`. `describeRoutes` lists every route with its access rule for a compile test. NestJS 11 and 12, Express.

### Patch Changes

- Updated dependencies [[`ceaae4c`](https://github.com/noctcore/auth/commit/ceaae4c11e265c833e34375e829cf34205cb07a5)]:
  - @noctcore/auth@0.3.0
