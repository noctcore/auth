The threat model of `@noctcore/auth`: what it protects, who it protects it from, where it trusts its surroundings, and which test proves each defense. The defenses are explained in the [Learn guide](https://noctcore.github.io/auth/learn/); each attack listed here has a numbered regression test in the [attack suite](https://github.com/noctcore/auth/blob/main/packages/auth/tests/attacks/ATTACKS.md).

## What the library is

A server-side library. A consuming app calls it from its own HTTP handlers to register, log in, validate a session, reset or change a password and verify an email address. The library never handles HTTP itself: the app passes in the request metadata (client IP, user agent, origin) and turns results into responses. Everything it stores goes through four store ports (users, sessions, one-time tokens, counters), with adapters for Redis and Prisma, and every mail goes through a mailer port. The optional two-factor plugin (`@noctcore/auth/two-factor`) adds a fifth store (factors, recovery codes, trusted devices, step-up proofs) and a cipher port for TOTP secrets.

## Assets

| Asset | Where it lives | What losing it means |
|---|---|---|
| Passwords | Never stored; only an Argon2id hash in the user store | Account takeover here and anywhere the password is reused |
| Password hashes | User store | Offline guessing; slowed by Argon2id, not stopped |
| Session tokens | The browser cookie; the store holds only their SHA-256 | Signing in as the user until the session ends |
| Reset and verification links and codes | The user's mailbox; the store holds a SHA-256 (links) or an HMAC under the server secret (codes) | Taking over the account, or verifying an address the attacker does not own |
| Trusted-device cookies | The browser; an HMAC under the server secret | Getting past a lock with a known password |
| The server secret | App configuration | Forging device cookies and CSRF tokens, and making stored code HMACs guessable offline |
| TOTP secrets (two-factor plugin) | The user's authenticator app; the store holds only what the app's cipher returns | Generating the user's codes, so the second factor is gone |
| Recovery codes (two-factor plugin) | With the user; the store holds an HMAC under the server secret, bound to the user | Getting past the second factor once per code |
| Two-factor trusted-device tokens | The browser cookie; the store holds their SHA-256 | Skipping the second factor, never the password, until the next password change, reset or revoke-all |
| Whether an address has an account | Nowhere on purpose | A list of users to phish or attack, and a privacy leak |
| The owner's ability to sign in | Lockout counters | Locking the owner out is a denial of service on one account |

## Trust boundaries

**The app** is trusted. It holds the configuration and the server secret, decides who may do what once a user is signed in, and renders every page. The library trusts the app to pass in correct request metadata, and checks the configuration at startup instead of trusting it blindly: for example, it refuses a server secret shorter than 32 bytes, a password policy below 8 characters and Argon2id parameters below the OWASP floor, and its `parseTrustProxy` helper refuses `true`.

**The stores** (Redis, Postgres through Prisma, or an adapter the app writes) are trusted to keep what is written and to honour the port contracts: single-use consumption, atomic counters, keys that expire, and a session touch that never brings a deleted session back. The conformance suite in `@noctcore/auth/testing` checks an adapter against those contracts. The library limits what a store leak gives away: tokens are stored only as hashes and codes as HMACs, so a read-only dump does not hand out working credentials.

**The mailer** is trusted to deliver to the address it is given. A mailbox is treated as proof of control: proving one lifts a lock, verifies the address and ends every other session. No flow awaits delivery. Every mail (sign-up, email verification, password change, password reset, the reset request's job and the lockout notice) is handed to `mailer.send` and the flow answers without awaiting the promise `send` returns, so a delivery that is slow, or never settles, neither delays nor hangs a response. The call to `send` is still on the response path, though: whatever `send` does before it returns its promise counts toward the response time. Sign-up hands a taken address an `account-exists` mail and a new address a `verify-email` mail, so a `send` that renders the template before returning makes the two paths take different times (in review, a 40 ms template made taken-address sign-up more than 30 ms slower). `send` must only enqueue, with templates built and mail sent by a worker. A mailer that throws or rejects never changes the answer: the error is logged as `Mailer failed`. Delivery is at most once from the library: each mail is handed over once and never retried, so a dropped mail stays dropped unless the app's mailer or queue retries it (the `dedupeKey` on each event is safe to use as a job id). Enqueueing narrows the window in which mail can be lost but does not close it: the enqueue write itself is not awaited, so a process that exits, or a serverless runtime that freezes the instance after the response, between the answer and the moment that write settles loses the mail. The library has no flush or `waitUntil` hook yet ([#50](https://github.com/noctcore/auth/issues/50)). It also sets no timeout and no cap on pending sends, so during an outage in which `send` hangs, unsettled promises pile up in memory: give the mailer's enqueue a timeout (an optional limit in the library is [#51](https://github.com/noctcore/auth/issues/51)).

**Sign-up timing that the library does not equalise.** With the uniform registration answer, a taken and a new address hash the password and hand over one mail each, but the rest of the work differs: the taken path's insert fails where the new one succeeds, and the store calls differ by one round trip (attack A004 pins both sequences). Two more pieces of work run only for a new address and are awaited, so their time shows: the app's `afterRegister` hooks (keep them fast and queue slow work such as a welcome mail or a CRM call), and with `registration.autoLogin` the session it issues. `autoLogin` is only allowed with `revealExisting`, whose answer already names a taken address, so its cost reveals nothing new. `bun run bench:timing` measures the sign-up pair on the in-memory stores and `bun run bench:timing:stores` on Postgres (through Prisma) and Redis. On the real stores, on one laptop, the taken path measured a few milliseconds slower than the new one, enough for the benchmark to tell them apart; the size depends on the machine and the database: the failed insert costs more than a successful insert plus the token write. Over a network that gap is small next to jitter, but an attacker with many samples can average it out, so sign-up enumeration by timing is reduced, not closed. The register door's rate limit (10 a minute per IP by default) and a captcha bound how many samples an attacker gets.

**The cipher** (two-factor plugin) is trusted to encrypt and decrypt TOTP secrets, and to bind each ciphertext to the user id it is given. The plugin never holds a key: key management and rotation are the app's. A store dump without the key yields no TOTP secret; an attacker who runs code with the key yields every one.

**Plugins and callers of `auth.context`** are trusted code, like the app. They can call `issueSession`, and the two-factor plugin's enforcement lets through a session issued with `via: 'second-factor'`, which is a claim that the factor was checked; the library cannot tell a true claim from a false one. The core's re-issue labels are the exception: it accepts them only with a session it read live from the store for the same user.

**The proxy.** Only the number of proxies the app configures is trusted. The client IP is read that many hops from the right of `X-Forwarded-For`, so entries the client wrote never decide it. With no proxy configured, the header is ignored.

**The browser** is not trusted: everything it sends is attacker-controlled input. The library sets cookies so the browser protects them (`__Host-` prefix, `HttpOnly`, `Secure`, `SameSite=Lax`), and checks the Origin, `Sec-Fetch-Site` and a signed double-submit token against cross-site requests. Request bodies, cookies, tokens and codes are validated for shape before they reach a store key or a hash.

## Attacker capabilities

The attacker is assumed to be able to:

- send any number of requests from many IP addresses, in parallel, with any headers and bodies, including a spoofed `X-Forwarded-For`;
- measure response times precisely over many requests;
- know or guess the victim's email address;
- register accounts of their own, including one on the victim's address before the victim does;
- get the victim's browser to load a page they control (so they can send cross-site requests with the victim's cookies, though not read the responses);
- obtain an old session cookie, reset link or code (from a shared computer, a forwarded mail or a log) after it was used or revoked;
- read a copy of the database or a Redis snapshot (a backup or dump), without being able to write to the live store.

## In scope

The library defends against: guessing passwords and codes; locking the owner out of the password login; finding out which addresses have accounts, by the answer or by its timing; holding answers up through a slow mailer; replaying or reusing sessions, links and codes; keeping a session alive after a revocation, a password change or a reset; cross-site request forgery on the flows it serves; spoofing the client IP to escape rate limits; taking over an account registered on someone else's address; forging trusted-device cookies; and turning a leaked store into working credentials. With the two-factor plugin on, also: replaying or guessing a TOTP or recovery code, reusing a login challenge, getting a session past the second factor through the core's flows (sign-up with auto-login, a plain login, and re-issues, which need a session the core read live for the same user), resetting a password or turning the factor off without it, and a stolen trusted-device token outliving a password change.

## Out of scope

- **The app's own authorization.** The library says who the user is. Whether that user may read an invoice or delete a project is the app's decision and the app's code.
- **XSS in the host app.** Script running in the app's origin can act as the user: send requests with their cookies, read pages, and change the password through the app's own forms. `HttpOnly` keeps the session cookie itself out of reach, but no authentication library can defend a page that runs the attacker's code.
- **A compromised Redis or database with write access.** An attacker who can write to the stores can create sessions, reset counters and edit password hashes. The store is inside the trust boundary; protect it with network isolation, credentials and TLS.
- **A leaked server secret or app configuration.** Rotate the secret (CSRF tokens accept the previous one during rollover); device cookies and outstanding codes signed with it become void, and so do the two-factor plugin's recovery codes, whose HMAC key is derived from it: users with a factor must generate a new set after a rotation.
- **The mail provider and the user's mailbox.** Whoever controls the mailbox controls the account.
- **Weak configuration chosen by the app.** Defaults are the library's responsibility; overrides are the app's.
- **Volumetric denial of service.** Rate limits protect accounts and the hasher, not the network.
- **Phishing and malware on the user's device.** This includes a phishing page that relays a password and a TOTP code to the real site in real time: TOTP does not stop it, only origin-bound factors (WebAuthn) would.
- **Enrolling a factor for a required user who has none yet.** For that user the password is the only credential, so whoever has it can answer the enrollment challenge. The owner is mailed when the factor goes on.
- **A stolen session locking the second factor.** Step-up counts wrong codes in the same per-account budget as the login challenge, so a session holder can lock the factor (and the owner's challenge) for up to an hour at a time, as long as the session lives.
- **A recovery code spent by a race on one challenge.** Two proofs sent at once on one challenge can both be checked; one gets the session, and a recovery code sent as the other is spent anyway.
- **A two-factor challenge carried to another browser.** A challenge is bound only to the user agent it was issued to, which an attacker holding the challenge can copy. Its limits are its 5-minute life and 5 codes.

## Mapping to the attack suite

| Attack | Defense | Test |
|---|---|---|
| Brute force by parallel guesses | Attempts reserved before the verify, per (account, IP) and per account | A001 |
| Locking the victim out | Capped lock, no permanent tier, one backoff step per lock (not per request that crosses the limit), trusted-device bypass, reset lifts the lock | A002 |
| Account enumeration by the answer | Public codes that never name account state | A003 |
| Account enumeration by timing | Same store calls and one verify for every address at login and reset request; one hash, one mail and as many store round trips at sign-up | A004 |
| Holding responses up through a slow or hung mailer | Every mail handed to the mailer without waiting; at-most-once delivery, failures logged | A023 |
| The locked-account oracle | Unknown addresses lock too; a lock answers like a wrong password | A005 |
| Replaying a revoked session | The epoch fence | A006 |
| Reusing a password reset token | Atomic single-use consume, expiry checked after it | A007 |
| Cross-site request forgery | Origin allowlist, `Sec-Fetch-Site`, signed double-submit token, `SameSite=Lax` | A008 |
| Forging or hoarding trusted-device cookies | HMAC over user, epoch and issue time; shared device budget | A009 |
| A stolen session cookie outliving a password change | Every session revoked after the new hash is written | A010 |
| Spoofing the client IP | Trusted hops counted from the right; `parseTrustProxy` refuses `true` | A011 |
| Account pre-hijacking | Proving the mailbox ends every other session | A012 |
| Guessing a short code | Attempt cap counted atomically; a per-address budget across IPs | A013 |
| Verifying an address with someone else's proof | Codes bound to user and purpose; links checked against the session | A014 |
| A login rehash bringing back an old password | Compare-and-set rehash | A015 |
| A plugin minting a session outside the seam | No mint exposed to plugins | A016 |
| Replaying secrets from a leaked store | Only hashes and HMACs stored | A017 |
| Cookie tossing and reading the cookie from script | `__Host-` prefix, `HttpOnly` | A018 |
| Two spellings of one address | ASCII-only normalisation, non-ASCII refused | A019 |
| Exhausting the server with oversized passwords | Maximum length; oversized input verified as empty against the dummy hash | A020 |
| Passing an unsafe method as a safe one through case folding | ASCII-only method comparison | A021 |
| Turning a malformed breach-check response into a verdict through case folding | ASCII-only upper-casing before the format check | A022 |
| Replaying a TOTP code (two-factor plugin) | The last accepted step moves forward by compare-and-set | A036 |
| Submitting one TOTP code twice at once | Atomic step advance; the challenge is consumed atomically | A037 |
| Brute forcing the second factor from many IPs | Attempts reserved per account before the compare; capped lock; 5 codes per challenge | A038 |
| Reusing a login challenge | Consumed on success, 5-minute life, replaced by a new login, bound to the user agent | A039 |
| Using a login challenge as a session or reset ticket | A one-time token under its own purpose, never in the session store | A040 |
| Reusing a recovery code | Atomic single-use delete; regenerating replaces the set in one write | A041 |
| Brute forcing a recovery code | 50 random bits per code; guesses spend the factor budget | A042 |
| A trusted-device token outliving a password change | Bound to the revocation epoch, deleted with the revocation | A043 |
| Resetting a password without the second factor | The reset demands a code; the factor is never touched | A044 |
| Turning two-factor off without a proof | Step-up per session id; a password alone never records one | A045 |
| Confirming an enrollment with a wrong or stale code | Fresh auth, read from the live session, to start and to confirm; compare-and-set on the pending secret within 10 minutes | A046 |
| Telling two-factor refusals apart by timing | Stand-in secret decrypted, same store calls for unknown and wrong | A047 |
| Getting a session past the second factor through another flow | The session hook refuses every issue but the plugin's own and re-issues | A048 |
| Acting on a stale or borrowed second-factor proof | Expiry on the server clock, bound to one session, fresh auth (read from the live session) required too | A049 |
| Learning two-factor state from the answers | The factor is checked only after the password; one public code for every refusal | A050 |

A report that breaks one of these defenses, or shows an attack the table misses, is a vulnerability: see [SECURITY.md](https://github.com/noctcore/auth/blob/main/SECURITY.md).
