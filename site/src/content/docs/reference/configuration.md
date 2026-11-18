---
title: Configuration
description: Every createAuth option with its default, the reason for that default, and the file where it is set.
---

:::caution[Pre-release]
Nothing is published to npm yet, and the API can change until 1.0.
:::

`createAuth(config)` takes one object, typed `AuthConfig` (`packages/auth/src/core/config.ts`). Only four keys are required. Everything else has a default chosen for safety first: where published guidance disagrees, the stricter value wins. The configuration is checked once, at startup, and anything unsafe throws an `AuthConfigError` before the app serves a request; [Startup checks](#startup-checks) lists every refusal.

Paths below are relative to `packages/auth/src/` unless they name another package.

## Durations

Every time option takes a `Duration`: a number is **seconds**, a string carries its unit, one of `ms`, `s`, `m`, `h` or `d` (`'15m'`, `'1h'`, `'30d'`). One parser reads them all, so a TTL can never be read as milliseconds in one place and seconds in another. Source: `shared/duration.ts`.

## Required

| Key | What it is |
| --- | --- |
| `stores.users` | A `UserStore`: users and their password hashes. `@noctcore/auth-prisma` ships one. |
| `stores.tokens` | A `TokenStore`: one-time codes and links, stored only as hashes. `@noctcore/auth-prisma` ships one. |
| `stores.sessions` | A `SessionStore`. `@noctcore/auth-redis` ships one. |
| `stores.counters` | A `CounterStore`: rate limits and lockout. `@noctcore/auth-redis` ships one. |
| `password.hasher` | A `PasswordHasher`. Use `argon2id()` from `@noctcore/auth/argon2`. |
| `secret` | The server secret, a string or `Uint8Array` of at least 32 bytes. Separate keys are derived from it for code HMACs, trusted-device tokens and session handles, so one key never serves two purposes. Rotating it invalidates outstanding codes and device cookies, never sessions, changes every session handle (a client holding an old one gets `{ revoked: false }` and must list again; see [Session handles](/auth/learn/sessions-and-expiry/#session-handles)), and also every recovery code of the two-factor plugin (their HMAC key is derived from it): after a rotation, have every user with a factor regenerate their recovery codes. Keep it apart from your CSRF secret. |
| `mailer` | A `Mailer` whose `send(event)` enqueues the mail. Flows never await it, and each mail is handed over at most once. See [Mail into your templates and queue](/auth/build/mail/). |

Any store that passes the conformance suite in `@noctcore/auth/testing` is valid; see [Writing a store adapter](/auth/build/store-adapter/). Source: `create-auth.ts` (`assertRequiredConfig`), `crypto/keys.ts`.

## Password

Source: `password/policy.ts`, `password/breach.ts`, `create-auth.ts`.

| Key | Default | Why |
| --- | --- | --- |
| `password.policy.minLength` | `12` | Stricter than the auth guide's 8 or 10; see [Passwords](/auth/learn/passwords/). A configured minimum below 8 is refused. |
| `password.policy.maxLength` | `256` | Bounds the hashing work one request can make the server do. |
| `password.breachCheck` | none | Pass `pwnedPasswords()` to refuse passwords from known breaches (recommended); `false` or leaving it out runs no check. The check fails open: an outage accepts the password and is logged, counted and written to the audit trail as `password.breach_check_unavailable`. |

Length is counted in Unicode code points of the NFC form, so the same password typed on a phone and a desktop has the same length. There are no composition rules ("one digit, one symbol"): they push people toward predictable patterns, as NIST SP 800-63B notes, and the breach check does the job they were meant to do.

`pwnedPasswords(options)` takes `timeoutMs` (default `3000`), `fetch`, `userAgent` (default `noctcore-auth`) and `baseUrl` (default the public range API). Only the first five hex characters of the password's SHA-1 leave the server.

## Session

The `session` key takes the session options and two more keys, `cookie` and `freshAuthAge`. Source: `session/session-types.ts`, `session/session-manager.ts`, `flows/resolve-settings.ts`.

| Key | Default | Why |
| --- | --- | --- |
| `session.absoluteTtl` | `'24h'` | A session without "remember me" ends a day after sign-in however active it is, which bounds what a stolen cookie is worth. |
| `session.rememberMeTtl` | `'30d'` | The absolute lifetime with "remember me". It must not exceed the session store's `maxSessionTtlMs` (the Redis store's `maxSessionTtl`, also 30 days by default). |
| `session.idleTimeout` | `'30m'`, or `'7d'` with "remember me" | Ends sessions left open on a shared machine. Also accepts a function of `{ rememberMe, attributes }`, decided per session at sign-in. |
| `session.touchInterval` | `'60s'` | Last-active is written at most once a minute instead of on every request. Must be shorter than a fixed idle timeout. |
| `session.maxPerUser` | `10` | The oldest sessions beyond the cap are evicted when a new one is issued, after it is written, so concurrent sign-ins converge on the cap. `null` for no cap. |
| `session.attributes` | none | A schema with a zod-style `parse`, run on every read. Required when you declare session attributes, so a corrupt or old record is refused, not trusted. |
| `session.freshAuthAge` | `'10m'` | How recent a credential proof must be to revoke another session or every other session, so a stolen session cannot sign the owner out. The library's own doors (revoking devices, second-factor enrollment, step-up) read it from the live session in the store. Your own routes can ask for it with `auth.requireFreshAuth(session)`, which checks the object you pass, so pass the session `validateRequest` just returned; plugins have `context.requireFreshLiveSession(session)`, which re-reads it. |

### Session cookie

Source: `http/cookie.ts`.

| Key | Default | Why |
| --- | --- | --- |
| `session.cookie.name` | `'session'` | Base name. When the cookie is Secure it becomes `__Host-session`: the browser then requires Secure, `Path=/` and no `Domain`, so a sibling subdomain cannot set or overwrite it. Letters, digits, `_` and `-` only. |
| `session.cookie.secure` | `true` | Turn it off only for plain-HTTP local development. Also drops the `__Host-` prefix, from the device cookie too (`device` instead of `__Host-device`). |
| `session.cookie.sameSite` | `'lax'` | Keeps the cookie off cross-site subrequests and form posts while links into the site still work. Accepts a function of the request's `Origin` for an app that also serves a desktop shell; `'none'` without Secure is refused when a cookie is built, not at startup. The trusted-device cookies and the NestJS and tRPC adapters' CSRF, pre-session and blank session cookies get the same answer. |

The cookie is always HttpOnly. A session without "remember me" gets a browser-session cookie (no `Max-Age`).

## Registration

Source: `flows/resolve-settings.ts`.

| Key | Default | Why |
| --- | --- | --- |
| `registration.revealExisting` | `false` | A taken address gets the same answer as a new one, and its owner gets an `account-exists` mail, so registration cannot tell anyone who has an account. `true` answers `email_in_use` instead. |
| `registration.autoLogin` | `false` | Issue a session on registration. Allowed only with `revealExisting`, or the session would reveal that the account is new. Issuing it is work only a new address does, so it shows in sign-up timing, which the `email_in_use` answer already gives away. |

## Email verification

Source: `flows/resolve-settings.ts`.

| Key | Default | Why |
| --- | --- | --- |
| `emailVerification.kind` | `'code'` | A code typed by the signed-in user ties the proof to that account's session. `'link'` needs `urls.verifyEmail`. |
| `emailVerification.ttl` | `'15m'` for codes, `'24h'` for links | A short code is guessable over time, so it lives briefly; a 32-byte link is not, so it can wait in an inbox. |
| `emailVerification.digits` | `8` | The auth guide's length. Must be 6 to 9. |
| `emailVerification.maxAttempts` | `5` | Wrong guesses per code, counted atomically before each comparison. |
| `emailVerification.linkWithoutSession` | `false` | Link verification only (refused at startup with codes, and anything but `true` or `false` is refused). Also accepts a valid link opened with no session: it verifies the address and revokes every session, but signs nobody in. A session of another account is still refused. Put the token in the URL fragment and verify only on a POST from a click, never on a GET or on page load, or a mail scanner verifies the account by fetching the link. See [Email verification](/auth/learn/email-verification/) for the trade-off. |

## Password reset

Source: `flows/resolve-settings.ts`, `flows/password-reset-request.ts`.

| Key | Default | Why |
| --- | --- | --- |
| `passwordReset.kind` | `'link'` | A single-use link of 32 random bytes. `'code'` mails digits that are exchanged for a short ticket. Links need `urls.resetPassword`. |
| `passwordReset.ttl` | `'1h'` for links, `'15m'` for codes | Long enough to reach the inbox, short enough that an old mail is useless. |
| `passwordReset.digits` | `8` | Must be 6 to 9. |
| `passwordReset.maxAttempts` | `5` | Wrong guesses per code. |
| `passwordReset.ticketTtl` | `'10m'` | How long the ticket a verified code becomes can set the password. |
| `passwordReset.enqueue` | none | Puts the request on your queue; your worker calls `auth.jobs.processPasswordReset(job)`. Without it the job runs detached in-process, which keeps the response time independent of the address but is lost if the process dies. |
| `passwordReset.markEmailVerified` | `true` | A completed reset proves the mailbox, so it marks the address verified. |

## Email change

Source: `flows/resolve-settings.ts`, `flows/email-change.ts`. The flows also need `urls.revertEmailChange` and a user store with `changeEmail`, and throw an `AuthConfigError` on the first call without them. See [Email change](/auth/build/email-change/).

| Key | Default | Why |
| --- | --- | --- |
| `emailChange.kind` | `'code'` | A code typed in the signed-in session of the same account. `'link'` needs `urls.confirmEmailChange`, and the link works only in such a session. |
| `emailChange.ttl` | `'15m'` for codes, `'1h'` for links | |
| `emailChange.digits` | `8` | Must be 6 to 9. |
| `emailChange.maxAttempts` | `5` | Wrong guesses per code, counted atomically before each comparison. |
| `emailChange.revertTtl` | `'7d'` | How long the revert link mailed to the old address works. Shorter is refused: the owner may be away for a week. |
| `emailChange.blockAfterRevert` | `'30d'` | After a revert, how long the account may not change to the address it lost. |

## URLs

Source: `core/config.ts`, `flows/resolve-settings.ts`.

| Key | Default | Why |
| --- | --- | --- |
| `urls.verifyEmail` | none | `(token) => string`. Required for link verification. |
| `urls.resetPassword` | none | `(token) => string`. Required for link resets, which are the default, so most apps set it. |
| `urls.confirmEmailChange` | none | `(token) => string`. Required for link email changes. |
| `urls.revertEmailChange` | none | `(token) => string`. The revert link of an email change; the email change flows throw without it. |

Put the token in the path or the fragment, not the query string, and send `Referrer-Policy: no-referrer` on those pages so the token does not leak to other sites.

## Throttle

### Lockout

The login lockout. Source: `throttle/rules.ts`, `throttle/throttle.ts`; the reasoning is in [Brute force and lockout](/auth/learn/brute-force-and-lockout/).

| Key | Default | Why |
| --- | --- | --- |
| `throttle.lockout.perAccountIp` | 5 per `'15m'` | Stops one source guessing at one account without touching the owner on another network. |
| `throttle.lockout.perAccount` | 10 per `'15m'` | Against guessing spread over many sources: close to one attempt a minute. Spending it locks the account. |
| `throttle.lockout.baseLock` | `'5m'` | The first lock. Each further lock multiplies it by 3. |
| `throttle.lockout.maxLock` | `'1h'` | Cap on a single temporary lock. There is no permanent lock unless you opt into `permanent`, because a permanent lock lets an attacker lock the owner out. |
| `throttle.lockout.quietPeriod` | `'24h'` | The backoff resets only after this long without a new lock. |
| `throttle.lockout.perDevice` | 5 per `'15m'` | Under a lock, the attempts a trusted device gets, and also the budget all of an account's devices share. Holding many device cookies adds no guesses. |
| `throttle.lockout.deviceMaxAge` | `'30d'` | The oldest trusted-device cookie accepted, checked on use. |
| `throttle.lockout.permanent` | off | Opt in to a permanent tier: `{ afterLocks, trustedDevices? }`. After `afterLocks` temporary locks in a row (each within `quietPeriod` of the last; a successful sign-in or a completed password reset resets the count), the next lock holds until an admin calls `auth.lockout.clear`; a password reset does not lift it. For an address with an account the lock is kept under the user id, so it follows the account through an email change, and it ends the account's sessions; for an address with no account it is kept under the address and a sign-up on that address clears it. `afterLocks` must be a whole number of at least 1. Turning the tier off later stops login reading its marker, but `auth.lockout.inspect` still reports a leftover permanent lock until `auth.lockout.clear` lifts it. Trade-off: anyone who knows an address can lock its owner out on purpose (denial of service). Pair it with a captcha and per-IP rate limits. |
| `throttle.lockout.permanent.trustedDevices` | `true` | `true`: the lock deletes the account's sessions but keeps its device cookies, so the owner can still sign in from a known device with the usual device budgets; a session from such a sign-in may reauthenticate and change the password, but no session may change the email. Other ways in still mint a session in this mode, each needing a correct password or your SSO: an app's SSO through `issueSession`, a two-factor challenge started before the lock, and a login racing the revocation. `false`: the lock bumps the revocation epoch (every session and device cookie ends) and refuses every session door (issuing a session by any path, validating one, reauthentication, password change, email change, email verification) until an admin clears it. Because validation checks the lock, a session the background revocation failed to end is refused, and revoked, on its next request. The default mode adds no read per request. |
| `throttle.lockout.revealLocked` | `false` | Answer `account_locked` from login while the address is locked, with `retryAfterSeconds` for a temporary lock, instead of `invalid_credentials`. Unknown addresses lock and answer the same, but the answer tells anyone that the address is locked and when it lifts: an enumeration signal the generic answer does not give. Pair it with a captcha and per-IP rate limits. |

Each rule is `{ limit, window }`; a part you leave out keeps its default.

`auth.lockout.inspect({ email })` or `({ userId })` returns `{ locked, permanent, until }` for an address, and `auth.lockout.clear({ email | userId, meta })` lifts every lock on it, the permanent one included, resets its backoff, returns the state it found and writes an `account.lock_cleared` audit row. The clear is not atomic: a burst of failures running during it can lock the account again as soon as it is lifted. Both answer for any address, known or not, so expose them only on admin routes. The `onPermanentLock` hook (`{ userId, email, meta }`) runs off the response path when the permanent tier locks an account, after its sessions end (`onSessionsRevoked` hears `locked-permanently`), beside the `account.locked_permanently` audit row and a `lockout` mail with `permanent: true`. Source: `flows/lockout-admin.ts`, `flows/lock-notice.ts`.

### Door limits

`throttle.doors` overrides the per-door rate limits, each a `{ limit, window }` rule. Doors are keyed by client IP unless noted. Every limit fails closed: a counter store that cannot answer refuses the request. Source: `DEFAULT_DOOR_LIMITS` in `core/config.ts`.

| Door | Default | Keyed by |
| --- | --- | --- |
| `login` | 10 per `'1m'` | IP |
| `register` | 10 per `'1m'` | IP |
| `password-reset-request` | 10 per `'1m'` | IP |
| `password-reset-mail` | 3 per `'1h'` | user: reset mails one account can receive |
| `password-reset` | 10 per `'1m'` | IP |
| `password-reset-code` | 10 per `'1m'` | IP |
| `password-reset-code-address` | 5 per `'15m'` | address: code guesses for one email from every IP |
| `email-verification` | 10 per `'1m'` | IP |
| `email-verification-request` | 3 per `'1h'` | user: verification mails one account can request |
| `password-change` | 5 per `'5m'` | user |
| `reauthenticate` | 5 per `'5m'` | user |
| `email-change-request` | 3 per `'1h'` | user: email change requests one account can make |
| `email-change-address` | 3 per `'1h'` | address: email change requests naming one new address, from every account |
| `email-change` | 10 per `'1m'` | IP: confirming an email change |
| `email-change-revert` | 10 per `'1m'` | IP: using a revert link |

The per-address door has a trade-off: anyone who knows an address can spend its budget and block that address's code-mode reset for 15 minutes. Link-mode reset, the default, does not use it.

## Collaborators

None of these is required. Source: `core/config.ts`, `create-auth.ts`, `ports/`.

| Key | Default | What it does |
| --- | --- | --- |
| `captcha` | none | A `CaptchaVerifier`, checked on login, register and the reset request. Fails closed: a provider outage refuses the request with `captcha_unavailable`. `turnstile(options)` builds one for Cloudflare Turnstile. |
| `audit` | none | An `AuditSink`. Every flow emits an event for each success and each refusal, with the internal `reason`. Events that record a grant are awaited before the grant is returned; a failing sink never fails the flow. |
| `hooks` | none | Functions the flows call at fixed points, such as `sessionAttributes`, `beforeSessionCreate`, `beforePasswordReset`, `beforeEmailChange`, `afterRegister` and `onPermanentLock`. A hook can refuse with `refuse(code, reason)`. `afterRegister` is awaited and runs only for a new address, so its time shows in sign-up timing: queue slow work instead of awaiting it. `onSessionsRevoked` gets `{ userId, sessionIds, sessionHandles, reason, scope? }`: `sessionIds` are store keys for server-side use only, `sessionHandles` the same sessions' public handles, as `sessions.list` showed them. |
| `plugins` | `[]` | Plugins add hooks and flows, never endpoints. A plugin's flows appear on the auth object under its `id`. The two-factor plugin (`twoFactor` from `@noctcore/auth/two-factor`) is configured on its own; its options are in [Two-factor](/auth/build/two-factor/#wiring-the-plugin). The membership plugin (`membership` from `@noctcore/auth/membership`) is configured the same way; its options are in [Membership guards](/auth/build/membership/#wiring-the-plugin). So is the invitations plugin (`invitations` from `@noctcore/auth/invitations`), in [Invitations](/auth/build/invitations/#wiring-the-plugin). |
| `logger` | silent | Where the package reports what it cannot return: a failed breach check, a mailer or audit sink that threw. Messages never carry secrets. |
| `metrics` | no-op | Counters such as breach check outages and door refusals. Labels never carry user input. |
| `background.waitUntil` | none | Handed every background task's promise (mail, lock notices, a reset job without `enqueue`) as it starts, so a runtime that freezes after the response keeps it alive. See [Mail](/auth/build/mail/#keeping-sends-alive-and-bounding-them). `auth.flush()` waits for the same tasks on shutdown. |
| `background.timeout` | none | Stop waiting on a task after this long; logged and counted as `timed_out`. The task is not cancelled. |
| `background.maxPending` | none | While this many tasks are still running (timed out or not), new ones are dropped, logged and counted as `dropped`. Bounds memory when a mailer hangs. |
| `clock` | system clock | Injectable so tests move time instead of sleeping. |
| `random` | `crypto.getRandomValues` | Injectable for tests. |

## Startup checks

`createAuth` throws an `AuthConfigError` when:

- a store, `password.hasher` or `mailer` is missing;
- `password.policy.minLength` is below 8;
- `session.cookie.name` has characters other than letters, digits, `_` and `-`;
- `session.maxPerUser` is not a positive integer or `null`;
- `session.touchInterval` is not shorter than a fixed `idleTimeout`;
- `session.absoluteTtl` or `rememberMeTtl` is longer than the session store's `maxSessionTtlMs`;
- `registration.autoLogin` is set without `revealExisting`;
- link verification, link reset or link email change is chosen without its `urls` function;
- `emailVerification.linkWithoutSession` is set without `kind: 'link'`, or is not `true` or `false`;
- `emailVerification.digits`, `passwordReset.digits` or `emailChange.digits` is outside 6 to 9;
- `emailChange.revertTtl` is shorter than 7 days;
- a plugin requires `captcha` and none is configured;
- `background.timeout` is zero, or `background.maxPending` is not a whole number of at least 1.

Sources: `create-auth.ts`, `core/background.ts`, `flows/resolve-settings.ts`, `session/session-manager.ts`, `http/cookie.ts`, `core/plugins.ts`.

## Store and hasher options

These belong to the objects you pass in, not to `createAuth`.

### `argon2id(options)`

Source: `password/argon2.ts`.

| Option | Default | Why |
| --- | --- | --- |
| `memoryCost` | `19456` (19 MiB) | OWASP's memory floor. Raise it per machine; login rehashes old hashes, so raising it later costs nothing. |
| `timeCost` | `3` | The auth guide's pass count, stricter than OWASP's 2 at this memory. |
| `parallelism` | `1` | OWASP's recommendation. |
| `secret` | none | An optional pepper kept outside the database. Changing or losing it makes every hash unverifiable. |
| `unsafeAllowWeakParameters` | `false` | Parameters below every row of OWASP's equivalence table are refused unless this is set. Tests only. |

### `redisStores(redis, options)`

Source: `packages/auth-redis/src/options.ts`, `session-store.ts`.

| Option | Default | Why |
| --- | --- | --- |
| `prefix` | `'auth:'` | Key prefix, so several apps can share one Redis. |
| `maxSessionTtl` | `'30d'` | The longest session the store holds. At least your `session.rememberMeTtl`; `createAuth` refuses a longer session. |
| `epochTtl` | `'90d'` | How long a user's revocation epoch outlives its last write. Must be longer than `maxSessionTtl`, or the store refuses to start. If it ever lapses, the user's sessions fail closed. |
| `clock` | system clock | For tests. |

Run that Redis with `maxmemory-policy noeviction`: an evicting policy may drop an epoch (signing users out), a lockout counter (handing an attacker a fresh budget) or a lock key (ending a lock early).

### `prismaStores(options)`

Source: `packages/auth-prisma/src/user-store.ts`, `index.ts`.

| Option | Default | What it does |
| --- | --- | --- |
| `delegate` | required | `prisma.user`, or whichever model holds your accounts. |
| `tokenDelegate` | required | `prisma.authToken`. |
| `fields` | `id`, `email`, `emailVerified`, `passwordHash`, `deletedAt` | Column names on your user model. `deletedAt: null` turns soft deletion off. |
| `select` | none | Extra columns to read for your own user type. |
| `toUser` | the four auth fields | Maps a row to your user type. |
| `createData` | none | Values for your other required columns on sign-up, such as a tenant or a display name. |
