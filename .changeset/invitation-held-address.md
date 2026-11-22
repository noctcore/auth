---
'@noctcore/auth': minor
---

`invitations.register` now refuses an address held for the owner of an email change away from it that can still be reverted, with the answer it gives a taken address (`email_in_use`, the same audit row) and without spending the invitation. It used to create an account on the held address, so an intruder who changed an account's address could invite the old one and leave the owner's revert answering `email_revert_address_taken`. The account is read before the hold, so an email change confirmed between the two reads is still seen. New `isAddressHeld(email)` on the plugin context, so a plugin that creates users applies the same rule. Sign-up, invitation sign-up, `auth.isAddressHeld` and the plugin context now share one rule for a held address: a hold whose account is gone, or a store without `changeEmail`, holds nothing (as sign-up already treated it). The docs no longer list invitations among the paths an app must guard with `isAddressHeld` itself.

Behaviour change: `invitations.register` now refuses a held address it used to accept, and `auth.isAddressHeld` now answers `false` (it answered `true`) when the account holding the address is gone or the user store has no `changeEmail`. Plugin authors gain `isAddressHeld(email)` on the plugin context.
