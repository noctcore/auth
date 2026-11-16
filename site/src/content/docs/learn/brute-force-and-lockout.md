---
title: Brute force and lockout
description: Limiting password guesses without handing attackers a way to lock the owner out.
---

## What goes wrong

Without a limit, an attacker can try passwords against an account as fast as the server answers. The classic fix, locking the account after N failures, creates a second attack: anyone who knows an address can keep its owner locked out forever by failing on purpose. Limits keyed only on IP fail the other way, because attackers rotate through proxy networks while real users share office and mobile IPs.

## The rule

**Reserve the attempt before checking the password.** The counters are incremented before the hash runs, atomically, so fifty parallel guesses cannot all slip in before the first failure is recorded.

**Two budgets, for two attackers.**

- *Per account and IP*: 5 attempts per 15 minutes. One source guessing at one account runs out quickly, and when it does, only that source is refused; the owner on their own network signs in normally.
- *Per account*: 10 attempts per 15 minutes from all sources together, close to one guess a minute. A distributed attack on one account trips this one.

**Locks are short and capped.** Exhausting the account budget locks the account for 5 minutes, then 15, then 45, capped at 1 hour, and the tier decays after a quiet day. There is no permanent lock. A correct password resets the budgets the source spent; a completed password reset lifts the lock and its history, since it proves the mailbox.

**The owner hears about it.** The first lock mails the account owner, who can reset the password if the attempts were not theirs.

**A lock looks like a wrong password.** See [Enumeration](/auth/learn/enumeration/): the counters are keyed on the address so unknown addresses lock too, and the answer is `invalid_credentials` either way.

**Every door has its own limit.** Login, sign-up, reset requests, code checks and password changes each have a fixed window per IP or per user. Limits fail closed: if the counter store is down, the request is refused, not let through.

## Where the package and the guide differ

The guide advises against account lockouts and exponential backoff, for exactly the victim-lockout reason above, and suggests a token bucket of about one attempt a minute per user. The package keeps a lockout because the owner chose one, but shapes it to remove the abuse: the per-(account, IP) budget isolates an attacker's source, the account-wide lock is capped at an hour with no permanent tier, and its rate is close to the guide's one a minute. It also agrees with the guide's warning on strict IP limits: the per-IP door limits are generous (10 a minute) and exist to stop floods, not guessing.

## Further reading

- [Passwords](https://auth.pilcrowonpaper.com/passwords), rate limiting section, in Pilcrow's auth guide.
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), account lockout.
