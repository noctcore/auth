---
title: Invitations
description: Why an invitation link is a credential, the ways invitation flows hand out accounts and seats they should not, and the rules the invitations plugin follows.
---

## What goes wrong

An invitation is a link that grants something: a seat in an organisation, a role, sometimes a whole account. Whoever holds it gets that, so it is a credential, and invitation flows tend to fail in the ways credentials fail, plus a few of their own:

- the link is **replayed**: clicked twice, opened in two browsers, or reused from a log after the invitee accepted, and a check-then-delete lets each request grant the seat again;
- the link **leaks** (a forwarded mail, a shared screen, a proxy log that recorded the query string) and someone signed in as themselves accepts it;
- an attacker **registers the address first**, never verifies it, and waits: an invitation that attaches to "the account with that address" hands the attacker the seat, and the victim later inherits an account the attacker still has a password for (account pre-hijacking);
- accepting **logs the invitee in**, so reading the victim's mail is enough to get past their second factor;
- the invite form becomes an **oracle** ("this user is already registered") or a **mailer** that floods a victim from a loop;
- anyone can invite, or an invitation sent by an admin who was demoted, or whose account was cleaned up after a takeover, **still works** later.

## The rules

**The token is treated like a password reset token.** 256 bits from the CSPRNG, sent once in the mail, stored only as an HMAC under a key derived from the server secret for invitations alone, so a leaked table holds no link and an invitation hash can never be confused with any other. It expires after 7 days by default, never more than 30, and an expired invitation answers exactly like one that never existed. The link carries the token in the path or the fragment, never the query string, which servers and proxies log; the plugin refuses a `url` that puts it there.

**Spending is one atomic step.** The store's `consume` removes and returns the invitation at once; only the request that got it goes on to grant anything. Of many concurrent accepts exactly one succeeds (attack A069). The conformance suite checks that every store gives this guarantee, under concurrency.

**The invitation belongs to an address, and only a verified owner of it can collect it.** Accepting into an existing account needs that account's address to be verified and equal to the invited one, both normalised (A070). An unverified account is never attached and spends nothing: the squatter who registered the address first gets nothing (A071). Creating an account from the invitation is allowed only when the address has none; then the token, delivered to that mailbox, is proof enough to mark the new address verified. That is the only case where the plugin verifies an address.

**Accepting never replaces signing in.** `accept` works on a session the user already has and issues none. `register` issues a session only for an account it just created, and through the same seam as every other session, so a second factor the app requires is asked for there too (A073). An account with a factor is never entered through an invitation.

**The inviter's side is uniform and bounded.** Creating an invitation never looks up the invited address, so the answer and the mail are the same whether it has an account or not (A074). There is at most one live invitation per scope and address, and a repeat sends nothing; each address can receive only a few invitations a day across all scopes, each inviter can send a limited number, and each IP is limited too (A075).

**Permission is the app's, and it is asked every time.** The plugin will not start without an `authorize` check, asks it for every create, list and revoke with the user read from the store, and asks it again for the inviter when an invitation is accepted. An inviter who lost the right or the account leaves nothing acceptable behind, and revoking all of an inviter's sessions deletes their pending invitations (A076).

## What it does not do

It does not tell the invited person from whoever reads the link. The token proves the mailbox, by design, so anyone holding a leaked link can `register` the invited address while it has no account yet: they get an account on that address, verified, with the invited seat. Keep the lifetime short and revoke an invitation you suspect leaked; once the address has an account, the link only works for that account, signed in.

It does not hide whether an address has an account from someone holding a live invitation to it: creating an account from the link is refused for a taken address, so that person can sign in instead. The holder is normally the owner of the mailbox, who can learn the same by asking for a password reset. It does not decide what a seat or a role means, and it does not filter your queries by organisation: that is your app, in `onAccept` and in every request.

How to wire it: [Invitations](/auth/build/invitations/) in Build.
