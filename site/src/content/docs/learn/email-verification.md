---
title: Email verification and account pre-hijacking
description: Proving a mailbox with a short code, binding the proof to the right account and address, and why verifying ends other sessions.
---

## What goes wrong

An unverified address is a claim. If the app trusts it (sends invoices there, lets an invitation attach to it, links a social login to it), someone can claim an address they do not own.

The sharper version is account pre-hijacking. The attacker registers the victim's address before the victim does, with a password the attacker knows, and stays signed in. Later the real owner arrives, proves the mailbox through a reset or a verification, and starts using the account, while the attacker's old session is still live inside it.

## The rule

**A code, typed by the signed-in user.** By default verification mails an 8-digit code instead of a link. The code is entered on the device that started the flow, by a user who is signed in, so the proof is tied to that account's session. A code sent to one account cannot verify another, even if both are open in the same browser.

**Bound to the address it was sent to.** The address is stored with the code, and verification only succeeds if the account still has that address, so a code mailed before an address change proves nothing about the new one. The store's write is guarded the same way.

**Short-lived, hashed, counted.** A code lives 15 minutes, is stored as an HMAC under a server secret, allows 5 wrong guesses (counted atomically before each comparison) and is deleted on success, expiry or exhaustion. Resending is limited to 3 mails an hour per account.

**Verifying ends every other session.** When the address is verified, every session of the account is revoked and the caller's own session is re-issued. A squatter who registered first is signed out the moment the real owner proves the mailbox. A completed password reset does the same, and also marks the address verified, since the reset link reached it.

**Links when you need them.** `emailVerification.kind: 'link'` mails a single-use link instead (32 random bytes, stored as SHA-256, 24 hours). The link only verifies when it is opened in a signed-in session of the same account; opened anywhere else, it is refused and left unspent, so the user can sign in and open it again. That keeps the pre-hijacking defence: a squatter's session can never be the one that completes verification.

## Where the package and the guide differ

The guide prefers codes, suggests 8 digits, and says a code at that rate limit need not be hashed or attempt-counted. The package follows the shape and is stricter on storage: codes are HMACed and capped at 5 attempts, which costs nothing and survives a leaked token table. The guide keys its rate limit on the email address; the package limits guesses per code (the attempt cap) and per IP, and resends per account.

## Further reading

- [Email address verification codes](https://auth.pilcrowonpaper.com/email-address-verification-codes) and [Email addresses](https://auth.pilcrowonpaper.com/email-addresses) in Pilcrow's auth guide.
- [Pre-hijacked accounts](https://www.microsoft.com/en-us/research/publication/pre-hijacked-accounts-an-empirical-study-of-security-failures-in-user-account-creation-on-the-web/), the study that named the attack.
