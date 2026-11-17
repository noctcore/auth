# @noctcore/auth

## 0.4.0

### Minor Changes

- [#59](https://github.com/noctcore/auth/pull/59) [`a78168e`](https://github.com/noctcore/auth/commit/a78168e668f7add8256d44596bd29a6455f61dd1) Thanks [@Shironex](https://github.com/Shironex)! - Add the two-factor plugin, `@noctcore/auth/two-factor`: TOTP (RFC 6238) with replay protection, ten single-use recovery codes, trusted devices, step-up for sensitive actions, and enforcement on every session the library issues. A password reset of an account with a factor asks for a code or a recovery code. Secrets are encrypted through a `SecretCipher` the app provides.
  
  - New store port `TwoFactorStore`, with `twoFactorStoreConformance` and `MemoryTwoFactorStore` in `@noctcore/auth/testing`.
  - Plugin seam: `PluginContext` gains `keyedHash`, `requireFreshAuth` and `cookie`; `Throttle` gains `gateFactor` and `factorSucceeded`.
  - New mail events `two-factor-enabled`, `two-factor-disabled` and `recovery-code-used`, and new `two_factor.*` audit event types. A mailer or audit sink that switches over every type with a `never` check needs cases for them.
  - `issueSession` accepts the re-issue vias (`password-change`, `reauthenticate`, `revoke-others`, `email-verified`) only with an `inherit` the core read live from the store, for the same user, through the new `AuthCore.confirmLiveSession`, before the flow revoked anything. A revoked, expired, idle or hand-built session is refused, and `reauthenticate`, `changePassword` and `sessions.revokeOthers` answer `session_expired` (`session_not_active`) for one. `SessionManager` gains `findActive`.
  - A lock no longer resets the attempt counter: it holds the counter above the limit for as long as the lock lasts, and every further `limit + 1` failures under it raise the backoff tier (the running lock keeps its end time; a large parallel burst can raise the tier by more than one step). A request that read "no lock" just before another one set it is now refused, so a parallel burst over many connections gets no more than the budget, for the password lockout and the second factor alike.
  - **Rotating `secret` voids every recovery code** of the two-factor plugin, whose HMAC key is derived from it. After a rotation, have every user with a factor regenerate their recovery codes.
  - `twoFactor` checks `attempts` and `perIp` at creation: the limit must be a positive integer and the window positive.
  - `resetPassword` and `changePassword` check the new password against the policy before running the `beforePasswordReset` and `beforePasswordChange` hooks, so a refused password spends nothing a hook asked for.

## 0.3.0

### Minor Changes

- [#48](https://github.com/noctcore/auth/pull/48) [`ceaae4c`](https://github.com/noctcore/auth/commit/ceaae4c11e265c833e34375e829cf34205cb07a5) Thanks [@Shironex](https://github.com/Shironex)! - No flow awaits mail delivery any more. Sign-up, email verification (send and resend), password change, password reset, the reset request's job and the lockout notice from a password change call `mailer.send` and answer without awaiting the promise it returns, so a delivery that is slow, or never settles, no longer delays or hangs a response.
  
  Timing changes for consumers: responses no longer include the time the promise from `send` takes to settle, and a reset job run by `auth.jobs.processPasswordReset` resolves before its mail is delivered. The call to `send` is still on the response path: whatever `send` does before it returns its promise (rendering a template, opening a connection) counts toward the response time, and sign-up sends different templates for a taken and a new address. `send` must only enqueue, with templates built in a worker.
  
  Delivery from the library is at most once: each mail is handed over once, a `send` that throws or rejects is logged as `Mailer failed` and never retried, so retries belong to the app's queue. Enqueueing narrows the window in which mail can be lost but does not close it, because the enqueue itself is not awaited: a process that exits or a serverless instance frozen after the response can still lose it (no flush or `waitUntil` hook yet, [#50](https://github.com/noctcore/auth/issues/50)). Background sends have no timeout or cap, so give the enqueue a timeout ([#51](https://github.com/noctcore/auth/issues/51)).
  
  Type break: `PluginContext.mail` now returns `void` instead of `Promise<void>`. Plugin code that calls `.then` on `ctx.mail(...)`, or returns it where a `Promise<void>` is expected, no longer type-checks. Code that only awaited it still compiles (lint may flag the await of a non-promise) and behaves the same, minus the wait.
  
  The `afterRegister` hook stays awaited (an app may rely on its work being done before the answer), and its docs now say it runs only for a new address and so shows in sign-up timing: queue slow work instead of awaiting it. `registration.autoLogin` is documented as visible in sign-up timing too.

## 0.2.0

### Minor Changes

- [#4](https://github.com/noctcore/auth/pull/4) [`cdeddbf`](https://github.com/noctcore/auth/commit/cdeddbf146dc664734e8f52a49f53bae614529c1) Thanks [@Shironex](https://github.com/Shironex)! - Add `createAuth` and the flows: registration with a uniform answer, password login (captcha, door limit, capped lockout answered like a wrong password, rehash on login, second-factor challenge seam), email verification by 8-digit code (default) or link, password reset by link or by code exchanged for a ticket, password change, fresh authentication, and session management (list, revoke one with fresh auth, revoke others, revoke all, logout). Hooks (`sessionAttributes`, `beforeSessionCreate`, `onSessionValidate`, `loginChallenge`, `beforePasswordResetRequest`, `beforePasswordReset`, `beforePasswordChange`, `afterRegister`, `onSessionsRevoked`) and `definePlugin` let apps and plugins add refusals, attributes and namespaced flows; every session goes through one `issueSession` seam.

- [#4](https://github.com/noctcore/auth/pull/4) [`f138781`](https://github.com/noctcore/auth/commit/f138781408c66595004a5ae7e3e8ac3fa5de9c90) Thanks [@Shironex](https://github.com/Shironex)! - Add the core primitives: secure random tokens and numeric codes, SHA-256 and HMAC helpers with constant-time comparison, email normalisation (ASCII only: addresses with any non-ASCII character are refused, so apps with such stored addresses must migrate them before adopting), durations, `AuthResult` and the closed `AuthErrorCode` set, the password policy (length only, NFC), the `PasswordHasher` contract with a self-made dummy hash for timing parity, the Have I Been Pwned range check (fails open), session cookie helpers (`__Host-`, SameSite per origin), the CSRF Sec-Fetch-Site and Origin checks and the signed double-submit token, a Turnstile verifier that checks hostname and action, and trust-proxy and client IP helpers. Argon2id (19 MiB, t=3, p=1 by default, never below the OWASP floor) with `needsRehash` is in `@noctcore/auth/argon2`.

- [#4](https://github.com/noctcore/auth/pull/4) [`a222dc2`](https://github.com/noctcore/auth/commit/a222dc29c9134b286d8acb16b13b66da249a7ff6) Thanks [@Shironex](https://github.com/Shironex)! - Add the store interfaces (users, sessions, one-time tokens, counters), the mail and audit event types, the `SessionManager` (opaque tokens stored as SHA-256, absolute and per-session idle expiry, touch that never resurrects, the epoch fence on mint and validate, eviction over a per-user cap), single-use link tokens and HMAC-stored numeric codes with an atomic attempt cap, and the throttle (fail-closed fixed windows; lockout budgets per account and IP and per account with backoff capped at 1 h and no permanent tier). `@noctcore/auth/testing` ships the runner-agnostic store conformance suite, in-memory stores that pass it, and test fakes.

- [#47](https://github.com/noctcore/auth/pull/47) [`fe2e067`](https://github.com/noctcore/auth/commit/fe2e06730b09f54d2a06ea2d573ebfb977a8f5ae) Thanks [@Shironex](https://github.com/Shironex)! - **Warning:** early 0.x releases are not meant for production apps yet. The API may have breaking changes between minor versions until 1.0.
  
  First release of the packages. `@noctcore/auth` is the framework-free core (sessions, flows, throttling, store interfaces and conformance suite), `@noctcore/auth-redis` and `@noctcore/auth-prisma` are the store adapters, and this release includes the first hardening pass: an attack suite, a coverage gate, and property and mutation tests.

### Patch Changes

- [#16](https://github.com/noctcore/auth/pull/16) [`e61e894`](https://github.com/noctcore/auth/commit/e61e8945482bd23b4e432ced58145e09acdb973f) Thanks [@Shironex](https://github.com/Shironex)! - Add the package README, which `files` already listed, and point source comments at Learn pages that exist.

- [#42](https://github.com/noctcore/auth/pull/42) [`9305ef5`](https://github.com/noctcore/auth/commit/9305ef5548bc3ca5d10b058ece12795bcc44a89d) Thanks [@Shironex](https://github.com/Shironex)! - The Pwned Passwords breach check now upper-cases response lines in ASCII only before checking their format. Before, `toUpperCase()` folded some non-ASCII characters into ASCII ones (the ligature U+FB00 became "FF"), so a malformed or tampered line could pass the format check and count as a breach instead of making the check report "unavailable".

- [`7ca4a52`](https://github.com/noctcore/auth/commit/7ca4a522899e5802058de35e8887c9201b91c378) Thanks [@Shironex](https://github.com/Shironex)! - `verifyRequestOrigin` and `verifyFetchSite` now upper-case the request method in ASCII only before checking for GET, HEAD and OPTIONS. Before, `toUpperCase()` folded some non-ASCII letters into ASCII ones, so a method such as `OPTION` followed by a long s was treated as safe and skipped the check. Browsers and Node's HTTP parser refuse such methods, so this was not reachable from another site.
