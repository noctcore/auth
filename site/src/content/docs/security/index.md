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
- A locked account is answered exactly like a wrong password.

## CSRF

An Origin check plus a signed double-submit token.

## Breached passwords

The check uses the Have I Been Pwned k-anonymity range API. It fails open, so an outage does not block sign-ups, and each failure is counted so it stays visible.

## Password hashing

Argon2id at the OWASP floor: 19 MiB of memory, t=2, p=1. Hashes are rehashed on login when parameters change.

## Sessions and scope

- Redis is the only session store in v1.
- There is no OAuth in v1.

## How to report

Report vulnerabilities privately, following [SECURITY.md](https://github.com/noctcore/auth/blob/main/SECURITY.md).
