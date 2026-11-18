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

**Locks are short and capped.** Exhausting the account budget locks the account for 5 minutes, then 15, then 45, capped at 1 hour. The backoff rises one step per lock, not per request: requests that cross the limit while a lock is already running (a parallel burst that read "no lock" a moment before, or wrong passwords let through by a device cookie) still count, but leave the lock's end and its step alone. Every new lock renews a 24-hour quiet period; only a full day without a new lock resets the backoff to 5 minutes. There is no permanent lock unless the app opts into one (below). A correct password returns only the budget of the source that proved it (that network's per-(account, IP) budget, or that device's budget), never the account-wide one, so an attacker cannot reset the shared budget by signing in once. A completed password reset lifts the temporary lock and its history, since it proves the mailbox.

**The owner's own devices get through.** Capping the lock is not enough on its own: an attacker who spreads failures over many addresses can renew the lock every few minutes, all day. So every new session, issued only after a full login with every factor, comes with a signed device cookie (`__Host-device`, HttpOnly). Its HMAC binds a random device id to the user id, the user's revocation epoch and the issue time.

- *It only matters under a lock.* While the account is unlocked, a login takes the normal path whatever cookie it carries, so the owner can sign in as often as they like without touching any device budget.
- *Under a lock, it lets only a correct password through.* A login with a valid cookie is not refused by the lock. Before the password check, the attempt reserves a slot in its cookie's own budget and in a budget shared by all of the account's devices (5 per 15 minutes each), atomically, the same way the other counters are reserved. A correct password hands both slots back, so it costs nothing. A wrong one keeps them and also counts against the account-wide budget, like any other failure; once the devices together hold 5 slots, every cookie is refused until the window ends. Because the shared slot is taken before the check, holding ten cookies gives no more guesses than holding one, even when they all fire at once.
- *It expires.* The server refuses a cookie older than 30 days (`throttle.lockout.deviceMaxAge`), checked on use, whatever the browser kept. Every new session sets a fresh one.
- *It is revoked with the sessions.* A password change, a completed reset and "sign out everywhere" bump the revocation epoch, which voids every device cookie issued before them, so a stolen cookie dies with the stolen password.

The cookie skips no password check and grants no session. The test suite runs the hard cases: the owner signs in every hour while an attacker sends thirty failures an hour from fresh addresses (a stranger is refused every hour, the owner gets in); ten cookies minted before a reset are useless after it; fifty guesses spread over ten valid cookies during a lock get five password checks in all, and so do eighty wrong guesses fired at once from four cookies; and ten correct logins in a row with the cookie, locked or not, all succeed.

**The owner hears about it.** Each new lock mails the account owner once, who can reset the password if the attempts were not theirs.

**A lock looks like a wrong password.** See [Enumeration](/auth/learn/enumeration/): the counters are keyed on the address so unknown addresses lock too, a locked login still runs the full password verify, the lock's audit row and owner mail run off the response path, and the answer is `invalid_credentials` either way.

**Every door has its own limit.** Login, sign-up, reset requests, code checks and password changes each have a fixed window per IP or per user. Reset-code guesses are also counted per address, from every network, whether or not the address has an account or a code outstanding. Limits fail closed: if the counter store is down, the request is refused, not let through. They cannot survive a store that silently drops keys, though: on Redis, run with `maxmemory-policy noeviction`, because an evicted lock key ends a lock early and an evicted counter resets a budget.

## Opt-in: a permanent tier and an explicit locked answer

Some apps need what the defaults leave out on purpose. Both options are off unless you turn them on, and each gives something up.

**A permanent tier** (`throttle.lockout.permanent: { afterLocks }`). After `afterLocks` temporary locks in a row (each within the quiet period of the last), the next lock never lapses. In a row means with no successful sign-in between: a correct password proves the owner, so it resets the count (not the temporary backoff), and an attacker gains nothing by it. A completed password reset proves the mailbox and resets it too, with the temporary lock and its backoff. Only an admin lifts the lock, with `auth.lockout.clear({ email })` or `({ userId })`; `auth.lockout.inspect` reads the state. A password reset does not lift it, waiting does not either, and the clear is not atomic: a burst of failures running during it can lock the account again at once. For an address with an account the lock is kept under the user id, so moving the account to another address does not escape it; an address with no account reaches it too, kept under the address, and a sign-up on that address clears it so the new owner does not inherit it.

A lock that left sessions alive would be a way around it: a session could reauthenticate and move the account to an unlocked address. So the lock ends the account's sessions, and no session may change the email while it holds (attack A085). When it locks a real account, the owner gets a `lockout` mail with `permanent: true`, an `account.locked_permanently` audit row is written, and the `onPermanentLock` hook runs off the response path, the place to page support. Second-factor locks never escalate.

The cost is the attack this page opens with: anyone who knows an address can lock its owner out for good by failing on purpose from many IPs. The trusted-device bypass softens it: by default the owner's device cookie still lets a correct password through a permanent lock, with the usual device budgets, so the lock keeps strangers out without locking the owner out. In this mode the lock deletes the sessions without voiding the device cookies, and a session from a device sign-in may reauthenticate and change the password. A few other ways in still mint a session, each needing a correct password or your SSO: an app's SSO through `issueSession`, a two-factor challenge started before the lock, and a login racing the revocation. None of those sessions can change the email. Set `trustedDevices: false` only when the lock must hold against the owner too: the lock then bumps the revocation epoch, ending every session and device cookie, and refuses every session door (issuing a session by any path, validating one, reauthentication, password change, email change, email verification) until an admin clears it (attack A083).

**An explicit answer** (`throttle.lockout.revealLocked: true`). Login answers `account_locked` while the address is locked, with `retryAfterSeconds` for a temporary lock and none for a permanent one, instead of `invalid_credentials`. A wrong password and one source's spent budget keep the generic answer. The cost is enumeration: the answer tells anyone who tries the address that it is locked and when it lifts. Unknown addresses lock and answer the same after the same work, so it does not prove an account exists by itself, but it is a signal the uniform answer never gives (attack A084; see [Enumeration](/auth/learn/enumeration/)).

Whichever you turn on, put a [captcha](/auth/learn/captcha/) on login and keep the per-IP door limits, so locking an address costs the attacker real work, and keep the admin tools on admin-only routes: they answer for any address.

## Where the package and the guide differ

The guide advises against account lockouts and exponential backoff, for exactly the victim-lockout reason above, and suggests a token bucket of about one attempt a minute per user. The package keeps a lockout because the owner chose one, but shapes it to remove the abuse: the per-(account, IP) budget isolates an attacker's source, the account-wide lock is capped at an hour with no permanent tier by default, its rate is close to the guide's one a minute, and the owner's trusted devices bypass it. It also agrees with the guide's warning on strict IP limits: the per-IP door limits are generous (10 a minute) and exist to stop floods, not guessing.

## Further reading

- [Passwords](https://auth.pilcrowonpaper.com/passwords), rate limiting section, in Pilcrow's auth guide.
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), account lockout.
