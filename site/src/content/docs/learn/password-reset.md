---
title: Password reset
description: A reset is a login by mailbox; how the request stays quiet, how the token is spent once, and what a completed reset cleans up.
---

## What goes wrong

Whoever can reset a password owns the account, so the reset flow is a second login form with weaker defences unless it is built as carefully as the first. It can leak which addresses exist, its links can be replayed or leak through a `Referer` header, two tabs can race the same link, and a reset that leaves old sessions alive does not remove an intruder who already got in.

## The rule

**The request is uniform and does nothing on the response path.** `requestPasswordReset` validates the input, applies the per-IP limit and hands a job to your queue (or runs it detached). The job looks the account up, checks the per-account mail limit (3 an hour) and mails the link. Known and unknown addresses get the same answer in the same time.

**One live token, spent once.** A reset link is 32 random bytes, stored only as its SHA-256, valid for an hour. Issuing a new one replaces the old. Applying it runs in this order:

1. *Peek*: look the token up without spending it, so a typo in the new password does not burn the link.
2. *Check*: run the hooks (a second-factor plugin asks for its code here) and the password policy and breach check.
3. *Hash* the new password.
4. *Consume* the token atomically. Of two concurrent resets with the same link, exactly one gets past this step.
5. *Write* the new hash.

**Codes become tickets.** With `passwordReset.kind: 'code'` the mail carries 8 digits instead. A correct code is exchanged for a ticket valid for 10 minutes, and only the ticket can set the password. The code is checked once, with an attempt cap of 5 per code and a second cap of 5 guesses per 15 minutes per address from every network (known address or not, code outstanding or not), and never authorises the write itself.

**A completed reset cleans up.** Every session is revoked, every outstanding reset token is voided, the lockout is lifted (the mailbox was proved), the address is marked verified unless you turn that off, and the owner gets a "password changed" mail. No session is issued: the user signs in with the new password.

**Keep the token out of logs and referrers.** Put it in the URL fragment or path, not the query string, and serve the page with `Referrer-Policy: no-referrer`.

## Where the package and the guide differ

The guide does not prescribe a reset flow in detail; the package follows the original production flow and adds the stricter pieces: no work on the request path, peek before consume, revocation of every session and a mandatory notification mail. Apps whose invitation logic depends on `emailVerified` can set `passwordReset.markEmailVerified: false`.

## Further reading

- [Auth sessions](https://auth.pilcrowonpaper.com/auth-sessions) in Pilcrow's auth guide, on invalidating sessions after credential changes.
- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html).
