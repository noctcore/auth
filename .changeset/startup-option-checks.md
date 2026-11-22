---
'@noctcore/auth': minor
'@noctcore/auth-nestjs': minor
'@noctcore/auth-trpc': minor
---

The startup option checks are finished: the value options listed below, which were read without a type check, now refuse a value of the wrong type when `createAuth`, a plugin, a factory (`argon2id`, `turnstile`, `pwnedPasswords`) or an adapter starts, with an `AuthConfigError` that names the option, instead of a raw `TypeError` at startup or a crash on the first request that reads it.

The ports (`logger`, `clock`, `metrics`, and the `logger` of `turnstile` and `pwnedPasswords`) are not checked.

- `throttle: { lockout: null }` boots with the defaults, like a missing `lockout` (it threw a `TypeError`).
- A duration that does not parse (`'15 min'`, `NaN`, a negative number) throws an `AuthConfigError` naming the key instead of a `TypeError` from the parser: the flow `ttl`s, `passwordReset.ticketTtl`, `emailChange.revertTtl` and `blockAfterRevert`, the `session` durations, the `throttle.lockout` durations and rule windows, `background.timeout`, and the plugins' durations and rule windows.
- A missing `csrf`, `csrf.secrets` or `csrf.allowedOrigins` in either adapter throws an `AuthConfigError` naming it instead of a `TypeError`.
- A `session.idleTimeout: null` now gives the default on every sign-in; it passed the startup check and then threw on each sign-in.
- A `null` `twoFactor` `required`, `enforcement` or `importedRecoveryCodes`, a `null` `previousSecret`, `background`, `background.maxPending`, `clientIpHeader` and `argon2id(null)` or `pwnedPasswords(null)` count as left out.

**Behaviour change:** a configuration that started before can now refuse to start. Each value refused was already broken (it crashed on first use, turned a check off, or quietly meant something else), but a deployment that passes one stops booting until it is fixed. Now refused:

- a list with an empty slot (`[, '/webhook']`, a hole in `csrf.secrets`, `csrf.allowedOrigins`, `csrf.crossSiteOrigins`, `csrf.exempt`, `previousSecret`, `plugins` or membership `adminRoles`): the checks walked the list with `.some` or `.every`, which skip a hole, and later code read it as `undefined`;
- an `emailVerification.kind`, `passwordReset.kind` or `emailChange.kind` other than `'code'` or `'link'` (a typo such as `'Link'` ran the other kind);
- a `urls` entry, `passwordReset.enqueue`, `background.waitUntil`, a plugin's `flows`, membership `canManage`, twoFactor `required`, or an adapter's `roles` that is not a function (each threw on the first request that called it);
- a `password.breachCheck` that is neither a function nor `false`, and a `captcha` without a `verify` function (the string `"false"` counted as configured, and the first sign-up or login threw);
- a `secret` that is neither a string nor bytes, a `session.cookie.name` that is not a string, a `session.attributes` without `parse`, and a fixed `session.cookie.sameSite` other than `'lax'`, `'strict'` or `'none'` (`'None'` skipped the check that refuses `None` without Secure; a function's value is checked the same way when a cookie is built);
- a `plugins` that is not a list of plugins with an `id`, or a plugin `requires` that is not a list;
- a `throttle.lockout` rule that is not an object (it fell back to the default silently);
- in `argon2id()`, an `unsafeAllowWeakParameters` that is not `true` or `false`, a cost parameter that is not a whole number of at least 1, and a `secret` that is not bytes;
- in `turnstile()`, a missing or empty `secret`, a `checkAction` that is not `true` or `false` (read by truthiness), an `expectedHostnames` given as one string (matched as a substring, so any part of the host name passed), a `timeoutMs` that is not a number above zero, and a `fetch` or `onResult` that is not a function; in `pwnedPasswords()` the same for `timeoutMs`, `fetch` and `onResult`, and a `userAgent` or `baseUrl` that is not a string;
- a `clientIpHeader` that is not a string (it was coerced with `String`);
- in `createAuthMiddlewares(t, { rateLimits })` and `rateLimited(name, rule)`, a rule that is not an object, a `limit` that is not a whole number of at least 1 (a `NaN` or zero limit refused every call), and a `window` that is not a duration longer than zero.

To fix a refused value, convert it first, for example `process.env.CHECK_ACTION === 'true'`, `Number(process.env.LIMIT ?? 10)`, or a list built with `.split(',')`.
