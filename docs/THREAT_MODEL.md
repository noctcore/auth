The threat model of `@noctcore/auth`: what it protects, who it protects it from, where it trusts its surroundings, and which test proves each defense. The defenses are explained in the [Learn guide](https://noctcore.github.io/auth/learn/); each attack listed here has a numbered regression test in the [attack suite](https://github.com/noctcore/auth/blob/main/packages/auth/tests/attacks/ATTACKS.md).

## What the library is

A server-side library. A consuming app calls it from its own HTTP handlers to register, log in, validate a session, reset or change a password, and verify or change an email address. The library never handles HTTP itself: the app passes in the request metadata (client IP, user agent, origin) and turns results into responses. Everything it stores goes through four store ports (users, sessions, one-time tokens, counters), with adapters for Redis and Prisma, and every mail goes through a mailer port. The optional two-factor plugin (`@noctcore/auth/two-factor`) adds a fifth store (factors, recovery codes, trusted devices, step-up proofs) and a cipher port for TOTP secrets. The optional membership plugin (`@noctcore/auth/membership`) adds a membership store (who holds which role in which scope) and guards the changes to it.

## Assets

| Asset | Where it lives | What losing it means |
|---|---|---|
| Passwords | Never stored; only an Argon2id hash in the user store | Account takeover here and anywhere the password is reused |
| Password hashes | User store | Offline guessing; slowed by Argon2id, not stopped |
| Session tokens | The browser cookie; the store holds only their SHA-256 | Signing in as the user until the session ends |
| Reset and verification links and codes | The user's mailbox; the store holds a SHA-256 (links) or an HMAC under the server secret (codes) | Taking over the account, or verifying an address the attacker does not own |
| Email change codes and revert links | The new address's mailbox (codes) and the old address's (revert links); the store holds an HMAC (codes) or a SHA-256 (links) | Moving the account to an address the attacker does not own; or, with a revert link, moving it back and removing its password |
| Trusted-device cookies | The browser; an HMAC under the server secret | Getting past a lock with a known password |
| The server secret | App configuration | Forging device cookies and CSRF tokens, and making stored code HMACs guessable offline |
| TOTP secrets (two-factor plugin) | The user's authenticator app; the store holds only what the app's cipher returns | Generating the user's codes, so the second factor is gone |
| Recovery codes (two-factor plugin) | With the user; the store holds an HMAC under the server secret, bound to the user | Getting past the second factor once per code |
| Two-factor trusted-device tokens | The browser cookie; the store holds their SHA-256 | Skipping the second factor, never the password, until the next password change, reset or revoke-all |
| Who may manage a scope (membership plugin) | The membership store: each member's role per scope | A scope nobody can manage, or a member who keeps powers taken away from them |
| Whether an address has an account | Nowhere on purpose | A list of users to phish or attack, and a privacy leak |
| The owner's ability to sign in | Lockout counters | Locking the owner out is a denial of service on one account |

## Trust boundaries

**The app** is trusted. It holds the configuration and the server secret, decides who may do what once a user is signed in, and renders every page. The library trusts the app to pass in correct request metadata, and checks the configuration at startup instead of trusting it blindly: for example, it refuses a server secret shorter than 32 bytes, a password policy below 8 characters and Argon2id parameters below the OWASP floor, and its `parseTrustProxy` helper refuses `true`.

**The stores** (Redis, Postgres through Prisma, or an adapter the app writes) are trusted to keep what is written and to honour the port contracts: single-use consumption, atomic counters, keys that expire, and a session touch that never brings a deleted session back. The conformance suite in `@noctcore/auth/testing` checks an adapter against those contracts. The library limits what a store leak gives away: tokens are stored only as hashes and codes as HMACs, so a read-only dump does not hand out working credentials.

**The mailer** is trusted to deliver to the address it is given. A mailbox is treated as proof of control: proving one lifts a lock, verifies the address and ends every other session. No flow awaits delivery. Every mail (sign-up, email verification, email change, password change, password reset, the reset request's job and the lockout notice) is handed to `mailer.send` and the flow answers without awaiting the promise `send` returns, so a delivery that is slow, or never settles, neither delays nor hangs a response. In most flows the call to `send` is still on the response path, though: whatever `send` does before it returns its promise counts toward the response time, and a door that mails on one branch only answers slower on that branch. `send` must only enqueue, with templates built and mail sent by a worker. Sign-up goes further: both of its mails (`account-exists` for a taken address, `verify-email` for a new one) are handed over from a background task, after a store call, so with a store that does network I/O the call to `send` comes after the answer (in an earlier review, a 40 ms template rendered inside `send` made taken-address sign-up more than 30 ms slower, when both mails were still handed over on the response path). A mailer that throws or rejects never changes the answer: the error is logged as `Mailer failed`. Delivery is at most once from the library: each mail is handed over once and never retried, so a dropped mail stays dropped unless the app's mailer or queue retries it (the `dedupeKey` on each event is safe to use as a job id). Enqueueing narrows the window in which mail can be lost but does not close it: the enqueue write itself is not awaited, so a process that exits, or a serverless runtime that freezes the instance after the response, between the answer and the moment that write settles loses the mail. The library has no flush or `waitUntil` hook yet ([#50](https://github.com/noctcore/auth/issues/50)). It also sets no timeout and no cap on pending sends, so during an outage in which `send` hangs, unsettled promises pile up in memory: give the mailer's enqueue a timeout (an optional limit in the library is [#51](https://github.com/noctcore/auth/issues/51)).

**Sign-up timing.** With the uniform registration answer, a taken and a new address both hash the password and the answer then waits on one insert: it stores a row for a new address and fails, or is skipped, for a taken one. Everything after the insert that differs between the paths runs off the response path: the owner lookup, the `account-exists` mail and the `register.existing` audit event for a taken address, the `register.created` event, the verification token and the `verify-email` mail for a new one (attack A004 pins both sequences and checks that the answer waits on none of them). With a user store that has `changeEmail`, every sign-up first looks for a hold on the address (an email change away from it can still be reverted), one indexed token read on every path before the insert; a held address reads its holder in the insert's place (A061). So sign-up answers before its mail is handed over and before its audit event is written, and a failure in that work is logged as `Background task failed`, not answered. On PostgreSQL and CockroachDB the Prisma user store inserts with `createManyAndReturn` and `skipDuplicates`, because on PostgreSQL through `@prisma/adapter-pg` a failed insert made the next query about 3 ms slower, which used to land on the owner lookup. Where Prisma refuses that (SQLite has no `skipDuplicates`; a `createData` with nested writes or relations cannot go through a bulk insert) the store falls back to `create` and a unique violation, which was not measured. Two pieces of work still run only for a new address and are awaited, so their time shows: the app's `afterRegister` hooks (keep them fast and queue slow work such as a welcome mail or a CRM call), and with `registration.autoLogin` the session it issues. `autoLogin` is only allowed with `revealExisting`, whose answer already names a taken address, so its cost reveals nothing new. The insert itself also differs (a stored row against a skipped one). `bun run bench:timing:stores` times the sign-up pair on Postgres (through Prisma) and Redis: before this change the taken path measured about 4.5 ms slower on one laptop (Welch's t about 20 over 200 samples per arm); after it, three seeds of 400 samples per arm gave |t| of 2.8, 1.7 and 0.1, under the 4.5 threshold the benchmark uses, on a machine that was heavily loaded during the run, which widens the spread and so hides small gaps. That is a measurement on one machine, not a guarantee: with a different database, a slower disk or an app's own hooks, a gap of the size of one insert can remain, so the register door's rate limit (10 a minute per IP by default) and a captcha still bound how many samples an attacker gets.

**The cipher** (two-factor plugin) is trusted to encrypt and decrypt TOTP secrets, and to bind each ciphertext to the user id it is given. The plugin never holds a key: key management and rotation are the app's. A store dump without the key yields no TOTP secret; an attacker who runs code with the key yields every one.

**Plugins and callers of `auth.context`** are trusted code, like the app. They can call `issueSession`, and the two-factor plugin's enforcement lets through a session issued with `via: 'second-factor'`, which is a claim that the factor was checked; the library cannot tell a true claim from a false one. The core's re-issue labels are the exception: it accepts them only with a session it read live from the store for the same user.

**The membership store** (membership plugin) is trusted to decide its two guarded writes atomically: a role change or a removal checks the member's current role and the other admins of the scope in the same step that writes, so concurrent writes cannot together leave a scope with no admin (`membershipStoreConformance` checks it under concurrency). The plugin reads the acting user's role from this store on every call, never from the session. Writes that bypass the store (an app's own SQL on the same table) are outside that guarantee.

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

The library defends against: guessing passwords and codes; locking the owner out of the password login; finding out which addresses have accounts, by the answer or by its timing; holding answers up through a slow mailer; replaying or reusing sessions, links and codes; keeping a session alive after a revocation, a password change or a reset; cross-site request forgery on the flows it serves; spoofing the client IP to escape rate limits; taking over an account registered on someone else's address; keeping an account by changing its email from a stolen session (the change needs fresh authentication and a live session, a proof from the new mailbox, and leaves the old address a revert link that a password change cannot void, held for its owner until the link is used or expires); forging trusted-device cookies; and turning a leaked store into working credentials. With the two-factor plugin on, also: replaying or guessing a TOTP or recovery code, reusing a login challenge, getting a session past the second factor through the core's flows (sign-up with auto-login, a plain login, and re-issues, which need a session the core read live for the same user), resetting a password, turning the factor off or requesting an email change without it, and a stolen trusted-device token outliving a password change. With the membership plugin on, also: leaving a scope without an admin through concurrent demotions or removals, acting on yourself (self-promotion, demoting or removing yourself), a demoted admin acting on the old role (the role is read from the store on every call), signing a stranger out by adding them and changing or removing them again, and, with `revokeSessionsOnChange` on, a demoted or removed member keeping a session, including through a login racing the change.

## Out of scope

- **The app's own authorization.** The library says who the user is. Whether that user may read an invoice or delete a project is the app's decision and the app's code. The membership plugin guards changes to roles; it does not scope data: filtering queries by tenant and checking membership on each request stay in the app.
- **Forced sign-out by a scope admin (membership plugin, `revokeSessionsOnChange` on).** The epoch is per user, so an admin of any scope a user belongs to can sign that user out everywhere, and void their trusted devices, by a real role change or a removal. That is the price of revoking at all; the option is off by default because the guards never need it. Who may be added to a scope, and whether they must agree first, is app policy: `add` takes a user id and asks no consent. The consent path is an invitation the user accepts (the invitations plugin, [#26](https://github.com/noctcore/auth/issues/26)). If revocation after the write fails, the change stands and the flow throws: every session from before the change was already revoked by the bump before the write, so only a login that ran between the two bumps can stay live; call `auth.context.revokeAllSessions(userId, 'membership-changed')` to finish.
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
- **What an email change revert does not restore.** A revert moves the address back, removes the password, and ends every session and trusted device. It never removes a second factor: it cannot tell the owner's from one the intruder enrolled, and removing factors by enrolment time would let whoever reads the old mailbox strip a factor the owner added just before a legitimate change (A063). A factor the intruder enrolled therefore stays, and the owner, who cannot pass it, needs support to verify them outside the account and remove it. The old address is held for its owner while the revert link lives, but only the library's sign-up and change flows check the hold: an app's own user-creating paths must call `isAddressHeld`, and sign-up checks before its insert, so a race (or a direct store write) can still give the address an account. The revert then cannot restore it; it locks the account out instead (no session from any flow, no reset mail, reset links refused) and keeps the link alive as long. The lockout never lapses (marker and link are stored to expire at the start of 9999-12-31 UTC); it ends only when the owner's revert finishes or when support calls `clearEmailRevertLockout`, which also voids the revert link and the hold; clearing it while the account names the intruder's address hands that address a reset. A revert link refuses once the account no longer names the address the change moved it to, so after support settles the account on another address the link cannot move it back, even years later when the old address frees up, and its clicks cannot lock the account out again (A062). A held address costs sign-up the same answer, mail and number of round trips before the answer as a taken one, not the same time (a read of the holder in the insert's place). While a revert link lives the account cannot start another change, even a legitimate one. Anyone signed in can spend a new address's request limit and stall changes to it for an hour. The flows are series of store calls, not transactions: confirm writes the revert link before it moves the address, and revert removes the password in the restore's write and revokes sessions right after, with the link unspent until the end so a click after a failure runs again. Whoever controls the old mailbox can use its revert link.
- **A two-factor challenge carried to another browser.** A challenge is bound only to the user agent it was issued to, which an attacker holding the challenge can copy. Its limits are its 5-minute life and 5 codes.

## Mapping to the attack suite

| Attack | Defense | Test |
|---|---|---|
| Brute force by parallel guesses | Attempts reserved before the verify, per (account, IP) and per account | A001 |
| Locking the victim out | Capped lock, no permanent tier, one backoff step per lock (not per request that crosses the limit), trusted-device bypass, reset lifts the lock | A002 |
| Account enumeration by the answer | Public codes that never name account state | A003 |
| Account enumeration by timing | Same store calls and one verify for every address at login and reset request; at sign-up one hash and one insert on the response path, the rest off it | A004 |
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
| Changing the email without a fresh credential proof | The request needs a password proof inside `freshAuthAge` | A051 |
| Changing the email of a two-factor account without the factor | A step-up in the session or a code with the request | A052 |
| Brute forcing the email change code | Attempt cap counted atomically before the compare; per-IP limit | A053 |
| Reusing an email change code or link | Atomic single-use consume; only hashes stored | A054 |
| Confirming an email change with a proof for another address or account | Codes bound to user and purpose; the token carries both addresses; compare-and-set on the old one | A055 |
| Keeping the account after an email change by changing the password | The revert link survives password changes and resets, removes the password and voids reset tokens | A056 |
| Replaying an email revert link | Purpose-bound, atomic single-use consume once the address is back | A057 |
| Account enumeration through the email change answer | Same answer and store calls for a taken, held and free address; the code only to a free one | A058 |
| Racing two email changes | One pending change per user; unique compare-and-set in the store | A059 |
| Taking the account back after a revert | No new change while a revert link lives; the lost address is blocked; tokens and trusted devices end; second factors stay (the intruder's needs support) | A060 |
| Registering the old address so the revert fails | The old address is held for its owner while the revert link lives and gets the taken-address answer; if it has an account anyway, the revert still removes the password and sessions and the link stays usable | A061 |
| Resetting the password at the intruder's address after a refused revert | A refused revert locks the account out: no session, no reset mail, reset links refused, each with the usual answer and no password hashed; it never lapses, ending only when the revert finishes or support clears it, which also voids the revert link and the hold; a link refuses once the account left the intruder's address | A062 |
| Stripping the owner's second factor with an email revert | A revert never removes a second factor, so a reset from the old mailbox still asks for the owner's | A063 |
| Leaving a scope without an admin by concurrent demotions or removals (membership plugin) | The store checks the other admins and writes in one atomic step | A060 |
| Acting on yourself through the membership flows | User ids compared before any lookup; the actor's role read from the store | A061 |
| Keeping a role or a scope after it was taken away | Every session revoked after the write; the epoch fence refuses a racing login | A062 |
| Leaving a scope without an admin by concurrent demotions or removals (membership plugin) | The store checks the other admins and writes in one atomic step | A061 |
| Acting on yourself through the membership flows | User ids compared before any lookup; the actor's role read from the store | A062 |
| Keeping a role or a scope after it was taken away | The actor's role read from the store on every call; with `revokeSessionsOnChange`, every session revoked before and after the write, and the epoch fence refuses a racing login | A063 |
| Signing a stranger out of everything through the membership flows | No revocation by default; never on an add or a same-role change | A073 |

A report that breaks one of these defenses, or shows an attack the table misses, is a vulnerability: see [SECURITY.md](https://github.com/noctcore/auth/blob/main/SECURITY.md).
