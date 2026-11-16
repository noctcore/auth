---
title: Enumeration
description: How an auth API leaks who has an account, through answers, timing and lockout, and how each door is kept quiet.
---

## What goes wrong

If a form answers "no account with this email" for one address and "wrong password" for another, anyone can test a list of addresses and learn who uses the service. For some services that fact alone is sensitive. It also makes guessing cheaper: the attacker spends their budget only on accounts that exist.

The answer text is the obvious leak. The less obvious ones are timing (a password hash takes tens of milliseconds, a missing row takes one), side effects (only real accounts get locked, only real accounts trigger mail on the request path) and every other door that takes an address: sign-up and password reset as well as login.

## The rule

**One answer per door.**

- *Login*: an unknown address, a wrong password, a locked account and an account a hook refused all answer `invalid_credentials`.
- *Registration*: a taken address answers exactly like a new one. Its owner gets an "account exists" mail instead of a verification mail, so a real person who forgot they had an account still learns it.
- *Password reset*: the request always answers the same.

**The same work on both paths.**

- Login makes the same store calls on every path: the address lookup, the epoch read and a credential lookup by id (under an id no store issues, for an unknown address), then one full password verify, against a dummy hash made with the same parameters when there is no real one. A locked account takes the same path: the verify still runs, its result is ignored.
- A new lock's audit row and owner mail are not awaited in the request; they run in the background with errors logged, so a known address does not answer slower than an unknown one.
- A reset-code check for an unknown address computes the same HMAC and makes the same token lookup as for a known one.
- The lockout counters are keyed on the normalised address, not on the user id, so an unknown address spends and checks counters exactly like a known one.
- Registration checks and hashes the password before it looks the address up.
- The reset request does none of the per-account work on the response path: looking up the account, its mail limit and the mail itself run in a job, on your queue or detached.
- Mail is handed to a `Mailer` that must enqueue, never send over SMTP inline.

**Errors carry two fields.** Every failure has a public `code` and an internal `reason` (`unknown_user`, `wrong_password`, `locked`). Only `toPublicError` output goes to the client; the reason goes to the audit trail and metrics.

## Where the package and the guide differ

The guide argues against hiding whether an account exists: full protection is hard, and a vague error confuses users. Where an identity must be protected, it suggests a username instead of an email. The package takes the stricter position by default, because its users sign in with an email: the uniform answers above are on unless an app opts out with `registration.revealExisting`, which turns the registration answer into `email_in_use`. Lockout stays uniform either way.

## Further reading

- [Passwords](https://auth.pilcrowonpaper.com/passwords), last section, in Pilcrow's auth guide.
- [Brute force and lockout](/auth/learn/brute-force-and-lockout/) for the counters behind the uniform lockout answer.
