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

**Links without a session, if you opt in.** Users often open the mail on another device, or after their session expired. `emailVerification.linkWithoutSession: true` also accepts a valid link opened with no session. What stays the same: the token is single-use, expires, and is bound to the account and to the address it was sent to, so a link for an address the account has since changed is refused. A link opened inside a session of another account is still refused and left unspent. What it never does is sign anyone in: the address is verified, every session of the account is revoked (the epoch is bumped, as on any verification, so a squatter's session ends) and no session is issued, so the user signs in afterwards. A user who opens the link signed in on the same account still gets their session re-issued.

**Verify on a click, never on a fetch.** With the option on, any request that carries the token verifies the address, and mail security scanners fetch links in mail before the reader sees them. If the page verifies on load, or the link points straight at an API route, the scanner verifies the account with nobody clicking. So:

- put the token in the URL fragment (`https://app.example/verify#<token>`), which a fetch never sends to the server;
- serve a page that shows what is being confirmed and a button, and do nothing on load;
- on the click, POST the token from the fragment to your route, which calls `verifyEmailLink` with the request's session (or `null`); never verify on a GET.

The [NestJS](/auth/build/nestjs/#verification-links) and [tRPC](/auth/build/trpc/#verification-links) guides show such a route.

**The trade-off.** By default whoever completes verification has just proven they hold the account's password. With the option on, nobody has to. A mailbox owner who clicks a link for an account someone else registered on their address verifies that account, and the registrant still knows its password: their sessions end, but they can sign in again to a now-verified account. With a route that verifies on a GET, a scanner does the clicking and nobody has to be fooled at all. Word the mail so the reader knows what they are confirming ("if you did not create an account, ignore this mail"), verify only on a POST from a click, and keep trust that matters (invitations, linking a social login) behind something the registrant cannot pass, such as a password reset. Leave the option off when that risk outweighs the convenience.

## Where the package and the guide differ

The guide prefers codes, suggests 8 digits, and says a code at that rate limit need not be hashed or attempt-counted. The package follows the shape and is stricter on storage: codes are HMACed and capped at 5 attempts, which costs nothing and survives a leaked token table. The guide keys its rate limit on the email address; the package limits guesses per code (the attempt cap) and per IP, and resends per account.

## Further reading

- [Email address verification codes](https://auth.pilcrowonpaper.com/email-address-verification-codes) and [Email addresses](https://auth.pilcrowonpaper.com/email-addresses) in Pilcrow's auth guide.
- [Pre-hijacked accounts](https://www.microsoft.com/en-us/research/publication/pre-hijacked-accounts-an-empirical-study-of-security-failures-in-user-account-creation-on-the-web/), the study that named the attack.
