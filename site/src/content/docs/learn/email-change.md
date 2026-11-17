---
title: Email change
description: Why changing the account's email needs a fresh credential, a proof from the new mailbox and a way back for the old one, and what a revert does.
---

## What goes wrong

The email address is the account's recovery channel: whoever controls it can reset the password. So an attacker who holds a session for a few minutes (a stolen cookie, an unlocked laptop) does not need to keep it. Changing the email to their own address and then resetting the password turns minutes of access into the account, for good, and the owner's own mailbox is no longer the one that gets the reset links.

Three weaker versions of the same flow help them further: a change that applies before the new address is proved (typos and squatting), a confirmation that says whether the new address already has an account (enumeration), and a notice to the old address that comes with no way to undo anything.

## The rule

**Fresh authentication, and the factor when there is one.** Asking for a change needs a session whose last password proof is inside `session.freshAuthAge`, 10 minutes by default. A stolen cookie on its own is refused (A051). With the two-factor plugin and a confirmed factor, the request also needs a step-up held by the session or a code with the request, the same rule as a password change (A052).

**Nothing changes until the new address proves itself.** The old address stays the login. An 8-digit code goes to the new address; it lives 15 minutes, is stored as an HMAC bound to the user, allows 5 wrong guesses counted before each comparison (A053), and is single use (A054). The stored row holds the new address and the one it replaces: a new request replaces the code, and a code for a change from an address the account no longer has is refused (A055). Like email verification, the code is typed in a live signed-in session of the same account, and a link (if you choose links) only works in one; a session revoked since the request cannot finish it. A pending change dies when the owner changes or resets the password, or signs out of other devices or everywhere.

**The same answer for a taken address.** A change to an address that already has an account, or that is held for another account (below), answers exactly like a change to a free one, after the same store calls; that address's owner gets an "in use" mail instead of a code (A058).

**Unique at the moment it applies.** The store moves the address in one compare-and-set on the old address, and the unique email column decides races: of two accounts confirming one address at once, exactly one gets it (A059).

**A confirmed change ends every other session and tells the old address at once.** Reset and verification tokens that went to the old address die and the revert link is written before the address moves, so no failure leaves a moved address without its way back. Every session of the account is then revoked through the epoch fence and the caller's is re-issued. The old address is mailed the new one and the revert link.

**The old address stays the owner's while the link lives.** Until the revert link expires or is used, the old address is held for the account that gave it up. Sign-up on it gives the answer for an address with an account and an "account exists" mail to the old address for its owner, with the same number of store round trips (reads, where a taken address does a failed insert, so the timing is not the same); another account's change to it answers as taken. Without the hold, the intruder could register the old address and leave the revert nowhere to go back to (A061). The hold only covers the library's own flows: an app's invitations, admin tools, first SSO sign-ins and imports must ask `auth.isAddressHeld` before they create a user.

**The old address can undo it.** The revert link is 32 random bytes stored as SHA-256, single use (A057), valid for 7 days or more, sent only to the old address and bound to it. Using it moves the account back and removes the password in one write, so the next sign-in needs a reset (mailed to the restored address); it then revokes every session and with them the two-factor plugin's trusted devices, voids every outstanding reset, verification and change token, removes a second factor enrolled since the session that asked for the change was created or last proved a credential, and writes an audit row flagged for review. A password change or a reset does not void the link (A056), and no second change can start while it lives, so the address it restores is the one the account had before the intruder came (A060).

**The link is spent only when the address is back, and a refused revert locks the account out.** If the old address has an account anyway (an app path that skipped the hold, a race between sign-up's check and its insert, or a direct store write), the revert still removes the password, revokes every session, trusted device and pending token and removes a late factor, answers `email_in_use` and writes an audit row flagged for review (A061). The account still names the intruder's address, so it is also locked out: no flow issues it a session, a reset request for it sends nothing and a reset link for it is refused, each with the usual answer (A062). The owner's link lives as long as the lockout. It ends when the owner's revert finishes once the address is free, when support clears it, or after 90 days.

**A repeat takeover is slower.** After a revert, the account may not change to the address it lost for 30 days (A060).

## Where the package and the guide differ

The guide's [email addresses](https://auth.pilcrowonpaper.com/email-addresses) page asks for a proof from the new address and a notice to the old one. The package adds the revert link, the fresh-auth and second-factor requirements, and the uniform answer for a taken address.

## What it does not cover

- A revert restores the address, not the rest of the account. A factor from before the session that asked for the change stays, so the owner's reset asks for it; one the intruder enrolled through an earlier session needs support.
- If the old address has an account anyway, the owner needs support to free it, and the lockout lapses after 90 days. Support clearing the lockout while the account still names the intruder's address would hand that address a working reset.
- The user cannot change the address again until the revert link expires (7 days by default), even if they made the first change themselves.
- Anyone signed in can use up a new address's request limit (3 an hour from every account) and stall changes to it for an hour.
- An intruder who also controls the old mailbox can use the revert link like the owner.

## Further reading

- [Email addresses](https://auth.pilcrowonpaper.com/email-addresses) in Pilcrow's auth guide.
- [Email verification and account pre-hijacking](/auth/learn/email-verification/), [Second factors](/auth/learn/second-factors/) and [Revocation races and the epoch fence](/auth/learn/revocation-races/).
