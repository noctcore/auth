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

**Locks are short and capped.** Exhausting the account budget locks the account for 5 minutes, then 15, then 45, capped at 1 hour. Every new lock renews a 24-hour quiet period; only a full day without a new lock resets the backoff to 5 minutes. There is no permanent lock. A correct password returns only the budget of the source that proved it (that network's per-(account, IP) budget, or that device's budget), never the account-wide one, so an attacker cannot reset the shared budget by signing in once. A completed password reset lifts the lock and its history, since it proves the mailbox.

**The owner's own devices get through.** Capping the lock is not enough on its own: an attacker who spreads failures over many addresses can renew the lock every few minutes, all day. So every successful login hands the browser a signed device cookie (`__Host-device`, HttpOnly, a year long), whose HMAC binds a random device id to the account. A later login that presents a valid one for that account skips the account lock and the shared budgets, and spends a small budget of its own instead: 5 attempts per 15 minutes per device. A failed login with the cookie counts against that device only. The cookie proves only that this browser once signed in to this account; it skips no password check and grants no session. The test suite runs exactly this case: the owner signs in every hour while an attacker sends thirty failures an hour from fresh addresses, and every hour a stranger is refused while the owner gets in.

**The owner hears about it.** The first lock mails the account owner, who can reset the password if the attempts were not theirs.

**A lock looks like a wrong password.** See [Enumeration](/auth/learn/enumeration/): the counters are keyed on the address so unknown addresses lock too, a locked login still runs the full password verify, the lock's audit row and owner mail run off the response path, and the answer is `invalid_credentials` either way.

**Every door has its own limit.** Login, sign-up, reset requests, code checks and password changes each have a fixed window per IP or per user. Reset-code guesses are also counted per address, from every network, whether or not the address has an account or a code outstanding. Limits fail closed: if the counter store is down, the request is refused, not let through.

## Where the package and the guide differ

The guide advises against account lockouts and exponential backoff, for exactly the victim-lockout reason above, and suggests a token bucket of about one attempt a minute per user. The package keeps a lockout because the owner chose one, but shapes it to remove the abuse: the per-(account, IP) budget isolates an attacker's source, the account-wide lock is capped at an hour with no permanent tier, its rate is close to the guide's one a minute, and the owner's trusted devices bypass it. It also agrees with the guide's warning on strict IP limits: the per-IP door limits are generous (10 a minute) and exist to stop floods, not guessing.

## Further reading

- [Passwords](https://auth.pilcrowonpaper.com/passwords), rate limiting section, in Pilcrow's auth guide.
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), account lockout.
