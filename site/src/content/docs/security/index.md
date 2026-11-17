---
title: Security defaults
description: The security choices the library makes by default, and how to report a problem.
---

:::note[Pre-release]
These are the defaults chosen for v1. The code that implements them is not published yet.
:::

## Registration

A registration answers the same way whether or not the email is taken. When the account already exists, the owner of that address gets an "account exists" mail instead of the caller seeing an `email in use` error, so registration cannot be used to find out who has an account.

## Email addresses

Addresses are trimmed and their ASCII letters lowercased; an address with any non-ASCII character is refused, which is stricter than NFC plus Unicode lowercasing (that folding can merge two different addresses into one account). Internationalised domains go in as punycode. An app adopting the package must find stored addresses with non-ASCII characters first, because their owners can no longer sign in or reset by them.

## Lockout

- There is no permanent lockout, because a permanent lock lets an attacker lock a victim out.
- Attempt budgets are keyed on account plus IP, and on the account as a whole.
- Backoff is exponential, capped at 1 hour, and resets only after a quiet day with no new lock.
- A correct password returns only the budget of the source that proved it, never the account-wide one.
- A browser that completed a full login carries a signed device cookie. It is used only while the account is locked, where it lets a correct password through; correct logins never spend a device budget, and wrong guesses count against a failure budget shared by all of the account's devices and against the account. The cookie is refused after 30 days and voided by a password change, a reset or signing out everywhere. A distributed attack cannot keep the owner out, and holding many cookies adds no guesses.
- The owner is mailed when the account locks; the mail is sent off the response path.
- A password reset lifts the lock.
- A locked account is answered exactly like a wrong password, after the same work: the same store calls and a full password verify.

## Sessions

- Revoking another device, or every other device, needs fresh authentication, so a stolen session cannot sign the owner out. Every door that asks for it (revoking devices, enrolling a second factor, a step-up check) reads it from the live session in the store, not from the session object it was handed.
- Plugins and `auth.context` see sessions without a way to mint one; every session goes through one internal seam.
- A login rehash is a compare-and-set, so it can never bring back a password changed meanwhile.

## CSRF

An Origin allowlist, a `Sec-Fetch-Site` check and a signed double-submit token bound to the session, or before sign-in to a random per-browser pre-session id, signed with its own secret of 32 bytes or more. See [CSRF](/auth/learn/csrf/).

## Breached passwords

The check is off until you pass `password.breachCheck: pwnedPasswords()` to `createAuth`. It uses the Have I Been Pwned k-anonymity range API and fails open, so an outage does not block sign-ups, password changes or resets, and each failure is counted and written to the audit trail as `password.breach_check_unavailable`.

## Password hashing

Argon2id with 19 MiB of memory, t=3, p=1: OWASP's memory floor with the auth guide's pass count. Parameters below OWASP's table are refused. Hashes are rehashed on login when parameters change. See [Passwords](/auth/learn/passwords/).

## Sessions and scope

- Redis is the only session store in v1.
- There is no OAuth in v1.

## How to report

Report vulnerabilities privately, following [SECURITY.md](https://github.com/noctcore/auth/blob/main/SECURITY.md).

## Where these come from

The defaults come from an implementation that already runs in production, checked against [Pilcrow's auth guide](https://auth.pilcrowonpaper.com/); where they disagreed, the stricter one was kept. [Design choices](/auth/learn/design-choices/) lists each case.
