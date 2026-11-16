---
title: Security defaults
description: The security choices the library makes by default, and how to report a problem.
---

:::note[Pre-release]
These are the defaults chosen for v1. The code that implements them is not published yet.
:::

## Registration

A registration answers the same way whether or not the email is taken. When the account already exists, the owner of that address gets an "account exists" mail instead of the caller seeing an `email in use` error, so registration cannot be used to find out who has an account.

## Lockout

- There is no permanent lockout, because a permanent lock lets an attacker lock a victim out.
- Attempt budgets are keyed on account plus IP, and on the account as a whole.
- Backoff is exponential, capped at 1 hour.
- The owner is mailed when the account locks.
- A password reset lifts the lock.
- A locked account is answered exactly like a wrong password.

## CSRF

An Origin allowlist, a `Sec-Fetch-Site` check and a signed double-submit token bound to the session. See [CSRF](/auth/learn/csrf/).

## Breached passwords

The check uses the Have I Been Pwned k-anonymity range API. It fails open, so an outage does not block sign-ups, and each failure is counted so it stays visible.

## Password hashing

Argon2id with 19 MiB of memory, t=3, p=1: OWASP's memory floor with the auth guide's pass count. Parameters below OWASP's table are refused. Hashes are rehashed on login when parameters change. See [Passwords](/auth/learn/passwords/).

## Sessions and scope

- Redis is the only session store in v1.
- There is no OAuth in v1.

## How to report

Report vulnerabilities privately, following [SECURITY.md](https://github.com/noctcore/auth/blob/main/SECURITY.md).

## Where these come from

The defaults come from an implementation that already runs in production, checked against [Pilcrow's auth guide](https://auth.pilcrowonpaper.com/); where they disagreed, the stricter one was kept. [Design choices](/auth/learn/design-choices/) lists each case.
