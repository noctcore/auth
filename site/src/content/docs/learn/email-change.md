---
title: Email change
description: Why changing the account's email needs a fresh credential, a proof from the new mailbox and a way back for the old one, and what a revert does.
---

## What goes wrong

The email address is the account's recovery channel: whoever controls it can reset the password. So an attacker who holds a session for a few minutes (a stolen cookie, an unlocked laptop) does not need to keep it. Changing the email to their own address and then resetting the password turns minutes of access into the account, for good, and the owner's own mailbox is no longer the one that gets the reset links.

Three weaker versions of the same flow help them further: a change that applies before the new address is proved (typos and squatting), a confirmation that says whether the new address already has an account (enumeration), and a notice to the old address that comes with no way to undo anything.

## The rule

**Fresh authentication, and the factor when there is one.** Asking for a change needs a session whose last password proof is inside `session.freshAuthAge`, 10 minutes by default. A stolen cookie on its own is refused (A051). With the two-factor plugin and a confirmed factor, the request also needs a step-up held by the session or a code with the request, the same rule as a password change (A052).

**Nothing changes until the new address proves itself.** The old address stays the login. An 8-digit code goes to the new address; it lives 15 minutes, is stored as an HMAC bound to the user, allows 5 wrong guesses counted before each comparison (A053), and is single use (A054). The stored row holds the new address and the one it replaces: a new request replaces the code, and a code for a change from an address the account no longer has is refused (A055). Like email verification, the code is typed in a signed-in session of the same account, and a link (if you choose links) only works in one.

**The same answer for a taken address.** A change to an address that already has an account answers exactly like a change to a free one, after the same store calls; that address's owner gets an "in use" mail instead of a code (A058).

**Unique at the moment it applies.** The store moves the address in one compare-and-set on the old address, and the unique email column decides races: of two accounts confirming one address at once, exactly one gets it (A059).

**A confirmed change ends every other session and tells the old address at once.** Every session of the account is revoked through the epoch fence and the caller's is re-issued. Reset and verification tokens that went to the old address die. The old address is mailed the new one and a revert link.

**The old address can undo it.** The revert link is 32 random bytes stored as SHA-256, single use (A057), valid for 7 days or more, sent only to the old address and bound to it. Using it moves the account back, removes the password so the next sign-in needs a reset (mailed to the restored address), revokes every session and with them the two-factor plugin's trusted devices, voids every outstanding reset, verification and change token, and writes an audit row flagged for review. A password change or a reset does not void the link (A056), and neither does a second change: while a revert link is live it is never replaced, so a later change gets none (A060).

**A repeat takeover is slower.** After a revert, the account may not change to the address it lost for 30 days (A060).

## Where the package and the guide differ

The guide's [email addresses](https://auth.pilcrowonpaper.com/email-addresses) page asks for a proof from the new address and a notice to the old one. The package adds the revert link, the fresh-auth and second-factor requirements, and the uniform answer for a taken address.

## What it does not cover

- A revert restores the address, not the rest of the account. A second factor stays in place, so the owner's reset asks for it; one the intruder enrolled needs support to remove.
- If someone registers the old address with another account before the owner reverts, the revert is refused and changes nothing.
- An intruder who also controls the old mailbox can use the revert link like the owner.

## Further reading

- [Email addresses](https://auth.pilcrowonpaper.com/email-addresses) in Pilcrow's auth guide.
- [Email verification and account pre-hijacking](/auth/learn/email-verification/), [Second factors](/auth/learn/second-factors/) and [Revocation races and the epoch fence](/auth/learn/revocation-races/).
