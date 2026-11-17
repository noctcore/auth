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

**Locks are short and capped.** Exhausting the account budget locks the account for 5 minutes, then 15, then 45, capped at 1 hour. The backoff rises one step per lock, not per request: requests that cross the limit while a lock is already running (a parallel burst that read "no lock" a moment before, or wrong passwords let through by a device cookie) still count, but leave the lock's end and its step alone. Every new lock renews a 24-hour quiet period; only a full day without a new lock resets the backoff to 5 minutes. There is no permanent lock. A correct password returns only the budget of the source that proved it (that network's per-(account, IP) budget, or that device's budget), never the account-wide one, so an attacker cannot reset the shared budget by signing in once. A completed password reset lifts the lock and its history, since it proves the mailbox.

**The owner's own devices get through.** Capping the lock is not enough on its own: an attacker who spreads failures over many addresses can renew the lock every few minutes, all day. So every new session, issued only after a full login with every factor, comes with a signed device cookie (`__Host-device`, HttpOnly). Its HMAC binds a random device id to the user id, the user's revocation epoch and the issue time.

- *It only matters under a lock.* While the account is unlocked, a login takes the normal path whatever cookie it carries, so the owner can sign in as often as they like without touching any device budget.
- *Under a lock, it lets only a correct password through.* A login with a valid cookie is not refused by the lock. Before the password check, the attempt reserves a slot in its cookie's own budget and in a budget shared by all of the account's devices (5 per 15 minutes each), atomically, the same way the other counters are reserved. A correct password hands both slots back, so it costs nothing. A wrong one keeps them and also counts against the account-wide budget, like any other failure; once the devices together hold 5 slots, every cookie is refused until the window ends. Because the shared slot is taken before the check, holding ten cookies gives no more guesses than holding one, even when they all fire at once.
- *It expires.* The server refuses a cookie older than 30 days (`throttle.lockout.deviceMaxAge`), checked on use, whatever the browser kept. Every new session sets a fresh one.
- *It is revoked with the sessions.* A password change, a completed reset and "sign out everywhere" bump the revocation epoch, which voids every device cookie issued before them, so a stolen cookie dies with the stolen password.

The cookie skips no password check and grants no session. The test suite runs the hard cases: the owner signs in every hour while an attacker sends thirty failures an hour from fresh addresses (a stranger is refused every hour, the owner gets in); ten cookies minted before a reset are useless after it; fifty guesses spread over ten valid cookies during a lock get five password checks in all, and so do eighty wrong guesses fired at once from four cookies; and ten correct logins in a row with the cookie, locked or not, all succeed.

**The owner hears about it.** Each new lock mails the account owner once, who can reset the password if the attempts were not theirs.

**A lock looks like a wrong password.** See [Enumeration](/auth/learn/enumeration/): the counters are keyed on the address so unknown addresses lock too, a locked login still runs the full password verify, the lock's audit row and owner mail run off the response path, and the answer is `invalid_credentials` either way.

**Every door has its own limit.** Login, sign-up, reset requests, code checks and password changes each have a fixed window per IP or per user. Reset-code guesses are also counted per address, from every network, whether or not the address has an account or a code outstanding. Limits fail closed: if the counter store is down, the request is refused, not let through.

## Where the package and the guide differ

The guide advises against account lockouts and exponential backoff, for exactly the victim-lockout reason above, and suggests a token bucket of about one attempt a minute per user. The package keeps a lockout because the owner chose one, but shapes it to remove the abuse: the per-(account, IP) budget isolates an attacker's source, the account-wide lock is capped at an hour with no permanent tier, its rate is close to the guide's one a minute, and the owner's trusted devices bypass it. It also agrees with the guide's warning on strict IP limits: the per-IP door limits are generous (10 a minute) and exist to stop floods, not guessing.

## Further reading

- [Passwords](https://auth.pilcrowonpaper.com/passwords), rate limiting section, in Pilcrow's auth guide.
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), account lockout.
