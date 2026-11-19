# @noctcore/auth-nestjs

## 0.6.0

### Minor Changes

- [#93](https://github.com/noctcore/auth/pull/93) [`5ef423f`](https://github.com/noctcore/auth/commit/5ef423f29ac787f97ec06e60e4bbefb672907732) Thanks [@Shironex](https://github.com/Shironex)! - The NestJS and tRPC adapters now work with a desktop shell served from its own scheme (such as `app://desktop`).
  
  - The CSRF cookie (`__Host-csrf`), the pre-session cookie (`__Host-presession`) and the blank cookie that clears a refused session take the session cookie's `SameSite` for the request's `Origin`, instead of a fixed `Lax`. A cookie written next to a new session takes that session cookie's own value. With the default `session.cookie.sameSite` (`'lax'`) nothing changes. An app that sets it to `'strict'`, `'none'` or a function now gets the same answer on these cookies too.
  - New `csrf.crossSiteOrigins` option in both adapters: exact origins whose cross-site requests are accepted. A listed origin passes the `Origin` check, and its `Sec-Fetch-Site: cross-site` requests pass the fetch-metadata check. The double-submit token is still required. Matching is exact (scheme, host and port). At boot, an entry fails if it is a wildcard, `null`, has no host, or carries a path, query, fragment or user info. The list is empty by default, so behaviour is unchanged until you name an origin. Trust a listed origin as much as your own: see the threat model.
  - Core: `resolveSameSite(config, origin)` gives the session cookie's `SameSite` for an origin (used by every cookie that travels with it), `verifyFetchSite` takes optional `origin` and `crossSiteOrigins` inputs, and `assertExactOrigins(origins, option)` checks an origin allowlist at boot. Each adapter also refuses `SameSite=None` when its cookies are not Secure, even if the cookie config claims they are.

- [#94](https://github.com/noctcore/auth/pull/94) [`8ca8e82`](https://github.com/noctcore/auth/commit/8ca8e82e4e136d31ccd46048541921ba567fc7bc) Thanks [@Shironex](https://github.com/Shironex)! - Trust proxies by address, and read the client IP from an edge header through a trusted hop.
  
  - `trustedHops` (in `clientIp` and in both adapters) also takes a list of proxy addresses, CIDR ranges and the Express presets `loopback`, `linklocal` and `uniquelocal`, which expand to the same ranges Express uses. With a list, `X-Forwarded-For` is read only when the socket address is inside it, and the first address outside it, from the right, is the client. `resolveTrustedProxies` checks and expands a list and refuses an unknown name, a malformed range or a range that holds every address (such as `0.0.0.0/0`); on the request path such a list trusts nothing instead of throwing. An IPv6 zone id on the socket address is dropped before matching. `isTrustedAddress`, `resolveTrustedHops`, `resolveClientIpHeader`, `TRUST_PROXY_PRESETS` and the `TrustedHops` type are exported too.
  - New opt-in `clientIpHeader` option in the NestJS and tRPC adapters (and `trustedHeader` in `clientIp`), such as `cf-connecting-ip`. It needs `trustedHops` as a proxy list naming the edge (it is refused at boot with a hop count, which never checks the socket address), and the header wins only when the socket address is inside that list and the value is exactly one valid IP; otherwise the `X-Forwarded-For` rule decides. Off by default, so nothing changes until it is set.
  - `trustedHopsFromEnv` and `configureTrustProxy` accept a `TRUST_PROXY` list such as `loopback, 10.0.0.0/8` and return it with the presets expanded (their return type is now `TrustedHops`, a number or a list); `configureTrustProxy` sets the same list on Express.

### Patch Changes

- [#124](https://github.com/noctcore/auth/pull/124) [`c2a26b4`](https://github.com/noctcore/auth/commit/c2a26b4af8954f9662bf72ed7ffaed15bbad1f53) Thanks [@Shironex](https://github.com/Shironex)! - A request that loses the race to adopt a legacy session (`adoptLegacySessions`) no longer signs the user out. Its refusal now carries the reason `session_adopting` (the new `adopting` session refusal) instead of `session_unknown`, and the new `clearsSessionCookie(result)` is false for it, so the NestJS CSRF middleware and the tRPC context keep the cookie and the next request finds the session the winning request wrote. Both adapters now decide whether to clear the session cookie through `clearsSessionCookie`. While the wrapper is installed, every token neither store knows is refused this way, so its cookie is kept until the user signs in again or the wrapper is removed; a malformed token and an old record the wrapper drops still clear it.

- [#111](https://github.com/noctcore/auth/pull/111) [`324401b`](https://github.com/noctcore/auth/commit/324401b039d245f21b5dd6f9d0595cf4fabecbc6) Thanks [@Shironex](https://github.com/Shironex)! - The two-factor plugin takes an `enforcement` option: a per-user policy, `({ user }) => { required, graceEndsAt? }`, so an app can require a factor of a tenant's existing users with a grace window. It is checked on every validated request, never stored, so a policy change or a closing window applies without a new sign-in. In the window the session carries `twoFactor: { state: 'grace', graceEndsAt }`; after it the user still signs in, but the session is `twoFactor: { state: 'enrollment-only' }` and the adapters let it reach only the routes marked for enrollment. A policy that throws reads as enrollment-only. `auth.twoFactor.sweepUnenrolled({ userIds })` revokes the sessions of users past their window without a factor (reason `two-factor-required`), and `status` reports the standing as `enforcement`. `enforcement` replaces `required`: pass one or the other.
  
  The core adds the `sessionStanding` hook, the `ValidatedSession`, `SessionStanding` and `TwoFactorStanding` types (`validateRequest` now returns a `ValidatedSession`), and the `two_factor_enrollment_required` error code. An app with an exhaustive map over `AuthErrorCode` needs an entry for it.
  
  `@noctcore/auth-nestjs`: `@TwoFactorEnrollment()` marks a route or controller an enrollment-only session may reach; the guard refuses it elsewhere with 403 `two_factor_enrollment_required`. `describeRoutes` reports `twoFactorEnrollment`.
  
  `@noctcore/auth-trpc`: `authed` (and `role`, `freshAuth` and `AuthGuardMiddleware`) refuse an enrollment-only session with `FORBIDDEN` `two_factor_enrollment_required` unless the procedure's meta says `twoFactorEnrollment: true`; the new `AuthProcedureMeta` type names the meta keys the adapter reads.
- Updated dependencies [[`5ef423f`](https://github.com/noctcore/auth/commit/5ef423f29ac787f97ec06e60e4bbefb672907732), [`89932e2`](https://github.com/noctcore/auth/commit/89932e2e1ee9c903e19db79643a58352263124d8), [`a78835e`](https://github.com/noctcore/auth/commit/a78835e018c59fb82863bcea122cf7d6fb4f6c82), [`1ac8ef2`](https://github.com/noctcore/auth/commit/1ac8ef25814bfed484dd94cd45f55ee107407712), [`bb44bef`](https://github.com/noctcore/auth/commit/bb44bef7700c67859180c2ab2290176daecc024a), [`8dd0bda`](https://github.com/noctcore/auth/commit/8dd0bda06892aa9ecab3ec4f69ee5e7158354cc5), [`e30dfba`](https://github.com/noctcore/auth/commit/e30dfbab3fb5af0f344ec3e70619a9517c8b20c6), [`c2a26b4`](https://github.com/noctcore/auth/commit/c2a26b4af8954f9662bf72ed7ffaed15bbad1f53), [`d66c19f`](https://github.com/noctcore/auth/commit/d66c19fd9445ec8879776e569f63f729e1d2d25f), [`0713d60`](https://github.com/noctcore/auth/commit/0713d60d21052e2d24c9ddd23a59225ec5e5a80e), [`67f1b27`](https://github.com/noctcore/auth/commit/67f1b273529f8612b9addd5ad8fa9f9210c75dd0), [`6e59447`](https://github.com/noctcore/auth/commit/6e59447af177ef851779d051b92044d5866e0d2b), [`6220dfe`](https://github.com/noctcore/auth/commit/6220dfe270fc94dd4f42fd25d52996f690458d93), [`c181c9a`](https://github.com/noctcore/auth/commit/c181c9a7ab5d1c80ab47adcaac5cbcabb1617c89), [`5144b55`](https://github.com/noctcore/auth/commit/5144b55b2e39d1dd82a71c3fdbfbaf184be45046), [`7258600`](https://github.com/noctcore/auth/commit/7258600446e61caaa4b0bcf44d904d4570f62fb1), [`8ca8e82`](https://github.com/noctcore/auth/commit/8ca8e82e4e136d31ccd46048541921ba567fc7bc), [`1c24674`](https://github.com/noctcore/auth/commit/1c246742eea9b734a74b8989c0f83557accb186a), [`324401b`](https://github.com/noctcore/auth/commit/324401b039d245f21b5dd6f9d0595cf4fabecbc6), [`ec705e8`](https://github.com/noctcore/auth/commit/ec705e8715df9d543c2672922de14a0f3547dd8d)]:
  - @noctcore/auth@0.6.0

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
