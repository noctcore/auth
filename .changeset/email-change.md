---
'@noctcore/auth': minor
'@noctcore/auth-prisma': minor
---

Add email change with a revert link: `requestEmailChange`, `confirmEmailChangeCode`, `confirmEmailChangeLink` and `revertEmailChange`.

- A request needs a live session with a credential proof inside `session.freshAuthAge`, then runs the new `beforeEmailChange` hooks. The two-factor plugin uses that hook: with a confirmed factor, the request needs a step-up held by the session or a code in `secondFactor`.
- An 8-digit code (or, with `emailChange.kind: 'link'` and `urls.confirmEmailChange`, a link) goes to the new address. A taken address gets the same answer after the same store calls, and its owner gets an `email-change-in-use` mail instead.
- A confirmed change moves the address in one compare-and-set, marks it verified, revokes every session (re-issuing the caller's with the new re-issue via `email-changed`), voids reset and verification tokens, and mails the old address `email-changed` with a revert link valid for `emailChange.revertTtl` (7 days, the minimum).
- A revert restores the old address, removes the password so the next sign-in needs a reset, revokes every session, voids reset, verification and change tokens, blocks the lost address for this account for `emailChange.blockAfterRevert` (30 days), and writes `email.change_reverted` with `review: true`. A live revert link is never replaced by a later change, and password changes and resets do not void it.
- New optional `UserStore.changeEmail`, returning `'changed' | 'taken' | 'stale'`, with conformance cases in `userStoreConformance` and an implementation in `MemoryUserStore` and `PrismaUserStore`. The flows need it and `urls.revertEmailChange`, and throw `AuthConfigError` without them. No schema change.
- New mail events `email-change-confirm`, `email-change-in-use`, `email-changed` and `email-change-reverted`, and new `email.change_*` audit event types. A mailer or audit sink that switches over every type with a `never` check needs cases for them.
- New doors `email-change-request`, `email-change-address`, `email-change` and `email-change-revert`; new revocation reasons `email-changed` and `email-reverted`; `OneTimeTokens.findLive`.
