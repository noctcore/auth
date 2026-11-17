The threat model of `@noctcore/auth`: what it protects, who it protects it from, where it trusts its surroundings, and which test proves each defense. The defenses are explained in the [Learn guide](https://noctcore.github.io/auth/learn/); each attack listed here has a numbered regression test in the [attack suite](https://github.com/noctcore/auth/blob/main/packages/auth/tests/attacks/ATTACKS.md).

## What the library is

A server-side library. A consuming app calls it from its own HTTP handlers to register, log in, validate a session, reset or change a password and verify an email address. The library never handles HTTP itself: the app passes in the request metadata (client IP, user agent, origin) and turns results into responses. Everything it stores goes through four store ports (users, sessions, one-time tokens, counters), with adapters for Redis and Prisma, and every mail goes through a mailer port.

## Assets

| Asset | Where it lives | What losing it means |
|---|---|---|
| Passwords | Never stored; only an Argon2id hash in the user store | Account takeover here and anywhere the password is reused |
| Password hashes | User store | Offline guessing; slowed by Argon2id, not stopped |
| Session tokens | The browser cookie; the store holds only their SHA-256 | Signing in as the user until the session ends |
| Reset and verification links and codes | The user's mailbox; the store holds a SHA-256 (links) or an HMAC under the server secret (codes) | Taking over the account, or verifying an address the attacker does not own |
| Trusted-device cookies | The browser; an HMAC under the server secret | Getting past a lock with a known password |
| The server secret | App configuration | Forging device cookies and CSRF tokens, and making stored code HMACs guessable offline |
| Whether an address has an account | Nowhere on purpose | A list of users to phish or attack, and a privacy leak |
| The owner's ability to sign in | Lockout counters | Locking the owner out is a denial of service on one account |

## Trust boundaries

**The app** is trusted. It holds the configuration and the server secret, decides who may do what once a user is signed in, and renders every page. The library trusts the app to pass in correct request metadata, and checks the configuration at startup instead of trusting it blindly: for example, it refuses a server secret shorter than 32 bytes, a password policy below 8 characters and Argon2id parameters below the OWASP floor, and its `parseTrustProxy` helper refuses `true`.

**The stores** (Redis, Postgres through Prisma, or an adapter the app writes) are trusted to keep what is written and to honour the port contracts: single-use consumption, atomic counters, keys that expire, and a session touch that never brings a deleted session back. The conformance suite in `@noctcore/auth/testing` checks an adapter against those contracts. The library limits what a store leak gives away: tokens are stored only as hashes and codes as HMACs, so a read-only dump does not hand out working credentials.

**The mailer** is trusted to deliver to the address it is given. A mailbox is treated as proof of control: proving one lifts a lock, verifies the address and ends every other session. A mailer that throws never changes the answer: the error is logged and the flow goes on. A slow mailer is another matter. Only the lockout notice and the password reset request's job send off the response path; sign-up, email verification, password change and password reset await the mailer before they answer, so a slow mailer slows those responses and a mailer that never settles keeps them waiting. Sign-up sends one mail whichever way it goes (a taken address gets "account exists" where a new one gets its verification mail), and password change and password reset mail only on success, so the count of sends does not reveal account state, but delivery time that differs between templates or recipients can show in the response time. Give the mailer a timeout, or have it enqueue and return. Moving every send off the response path is tracked in [#46](https://github.com/noctcore/auth/issues/46).

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

The library defends against: guessing passwords and codes; locking the owner out; finding out which addresses have accounts, by the answer or by its timing; replaying or reusing sessions, links and codes; keeping a session alive after a revocation, a password change or a reset; cross-site request forgery on the flows it serves; spoofing the client IP to escape rate limits; taking over an account registered on someone else's address; forging trusted-device cookies; and turning a leaked store into working credentials.

## Out of scope

- **The app's own authorization.** The library says who the user is. Whether that user may read an invoice or delete a project is the app's decision and the app's code.
- **XSS in the host app.** Script running in the app's origin can act as the user: send requests with their cookies, read pages, and change the password through the app's own forms. `HttpOnly` keeps the session cookie itself out of reach, but no authentication library can defend a page that runs the attacker's code.
- **A compromised Redis or database with write access.** An attacker who can write to the stores can create sessions, reset counters and edit password hashes. The store is inside the trust boundary; protect it with network isolation, credentials and TLS.
- **A leaked server secret or app configuration.** Rotate the secret (CSRF tokens accept the previous one during rollover); device cookies and outstanding codes signed with it become void.
- **The mail provider and the user's mailbox.** Whoever controls the mailbox controls the account.
- **Weak configuration chosen by the app.** Defaults are the library's responsibility; overrides are the app's.
- **Volumetric denial of service.** Rate limits protect accounts and the hasher, not the network.
- **Phishing and malware on the user's device.**

## Mapping to the attack suite

| Attack | Defense | Test |
|---|---|---|
| Brute force by parallel guesses | Attempts reserved before the verify, per (account, IP) and per account | A001 |
| Locking the victim out | Capped lock, no permanent tier, trusted-device bypass, reset lifts the lock | A002 |
| Account enumeration by the answer | Public codes that never name account state | A003 |
| Account enumeration by timing | Same store calls and one verify for every address at login and reset request; one hash, one mail and as many store round trips at sign-up | A004 |
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

A report that breaks one of these defenses, or shows an attack the table misses, is a vulnerability: see [SECURITY.md](https://github.com/noctcore/auth/blob/main/SECURITY.md).
