# @noctcore/auth-prisma

## 0.5.0

### Minor Changes

- [#63](https://github.com/noctcore/auth/pull/63) [`76717de`](https://github.com/noctcore/auth/commit/76717de578fbd4f83973dcf544acafeb1d5c9dad) Thanks [@Shironex](https://github.com/Shironex)! - Add email change with a revert link: `requestEmailChange`, `confirmEmailChangeCode`, `confirmEmailChangeLink` and `revertEmailChange`.
  
  - A request needs a live session with a credential proof inside `session.freshAuthAge`, then runs the new `beforeEmailChange` hooks. The two-factor plugin uses that hook: with a confirmed factor, the request needs a step-up held by the session or a code in `secondFactor`.
  - An 8-digit code (or, with `emailChange.kind: 'link'` and `urls.confirmEmailChange`, a link) goes to the new address. A taken address, or one held for another account, gets the same answer after the same store calls, and its owner gets an `email-change-in-use` mail instead. A confirm needs a live session of the same account. A pending change dies on a password change or reset and on signing out of other devices or everywhere.
  - A confirmed change voids reset and verification tokens and writes the revert link before it moves the address in one compare-and-set, marks it verified, revokes every session (re-issuing the caller's with the new re-issue via `email-changed`), and mails the old address `email-changed` with a revert link valid for `emailChange.revertTtl` (7 days, the minimum). While that link lives, the old address is held for the account: sign-up on it answers as for a taken address, and so do other accounts' changes to it.
  - A revert restores the old address and removes the password in one write, revokes every session, voids reset, verification and change tokens, keeps second factors (an owner who cannot pass one an intruder enrolled needs support), blocks the lost address for this account for `emailChange.blockAfterRevert` (30 days), and writes `email.change_reverted` with `review: true`. If the old address has an account anyway, it removes the password and sessions, answers `email_in_use`, and locks the account out: no session is issued for it, reset requests send nothing and reset links are refused, until the owner's link (kept alive as long) finishes or support calls the new `auth.clearEmailRevertLockout`, which also voids the revert link and the hold; it never lapses on its own. A revert link refuses once the account no longer names the address the change moved it to. New `auth.isAddressHeld(email)` for an app's own user-creating paths. No new change starts while a revert link lives, and password changes and resets do not void it.
  - New optional `UserStore.changeEmail`, returning `'changed' | 'taken' | 'stale'`, with conformance cases in `userStoreConformance` and an implementation in `MemoryUserStore` and `PrismaUserStore`. The flows need it and `urls.revertEmailChange`, and throw `AuthConfigError` without them. No schema change.
  - New mail events `email-change-confirm`, `email-change-in-use`, `email-changed` and `email-change-reverted`, and new `email.change_*` audit event types. A mailer or audit sink that switches over every type with a `never` check needs cases for them.
  - New doors `email-change-request`, `email-change-address`, `email-change` and `email-change-revert`; new revocation reasons `email-changed` and `email-reverted`; `OneTimeTokens.findLive`, `putKeyed`, `findKeyed` and `extendLink`; the `email.revert_lockout_cleared` audit event type.
  - `resetPassword` now checks the new password against the policy, then runs `beforePasswordReset`, and only then hashes, so a hook's refusal costs no hash. `AuthCore.checkNewPassword` and `hashCheckedPassword` split `hashNewPassword` for flows that run hooks between the two.

- [#71](https://github.com/noctcore/auth/pull/71) [`c09f611`](https://github.com/noctcore/auth/commit/c09f611bc86253f33220e6d6ace54743de5cc1af) Thanks [@Shironex](https://github.com/Shironex)! - Add stores for the invitations plugin: `RedisInvitationStore` in `@noctcore/auth-redis` (keys under `inv:`, each with a TTL at the invitation's expiry, create and consume each one Lua script) and `PrismaInvitationStore` in `@noctcore/auth-prisma`, which needs the new `AuthInvitation` model in `prisma/auth.prisma` and the client, for the transaction that replaces an expired invitation. Both pass `invitationStoreConformance`, including its concurrent consume and create cases, against Redis and PostgreSQL.

- [#64](https://github.com/noctcore/auth/pull/64) [`2ab09b7`](https://github.com/noctcore/auth/commit/2ab09b7b3769e14fbd72259138592df55a8bb3bb) Thanks [@Shironex](https://github.com/Shironex)! - Add stores for the membership plugin: `RedisMembershipStore` in `@noctcore/auth-redis` (one hash per scope under `ms:<scope>`, guarded writes in one Lua script) and `PrismaMembershipStore` in `@noctcore/auth-prisma`, which needs the two new models in `prisma/auth.prisma` (`AuthMember`, `AuthMemberScope`) and the client, for the version-guarded transaction behind every role change and removal. Both pass `membershipStoreConformance`, including its concurrent last-admin cases, against Redis and PostgreSQL.

- [#67](https://github.com/noctcore/auth/pull/67) [`f53c320`](https://github.com/noctcore/auth/commit/f53c320a48e887eba7b295f730cad16df6a1c6c7) Thanks [@Shironex](https://github.com/Shironex)! - `PrismaUserStore` (and `prismaStores`) take an optional `logger`. When Prisma refuses the skipped insert at sign-up (SQLite, a `createData` with nested writes) and the store switches to `create` for good, it warns once through that logger instead of switching silently. The warning carries no error text, because a Prisma validation message prints the whole call, the password hash included.

### Patch Changes

- [#65](https://github.com/noctcore/auth/pull/65) [`e73f7a0`](https://github.com/noctcore/auth/commit/e73f7a0096808eb2fa9f705fe6c32983fb752e08) Thanks [@Shironex](https://github.com/Shironex)! - Sign-up no longer waits on the work that differs between a taken and a new address. The answer waits on the door limit, the password hash and one insert; after that, a taken address's owner lookup, `account-exists` mail and `register.existing` audit event, and a new address's `register.created` audit event, verification token and `verify-email` mail, run in the background. On Postgres and Redis the taken path used to answer a few milliseconds slower, enough for `bun run bench:timing:stores` to tell the paths apart.
  
  On PostgreSQL and CockroachDB, the Prisma user store inserts through `createManyAndReturn` with `skipDuplicates`, so a taken address is a skipped insert instead of a failed statement. On PostgreSQL through `@prisma/adapter-pg`, a failed statement made the next query about 3 ms slower. Everywhere else the store keeps the old insert, where a unique violation answers `null`: on delegates without `createManyAndReturn` (MySQL, SQL Server), and where Prisma refuses the bulk insert with a validation error (SQLite, which has no `skipDuplicates`, and a `createData` or `select` with nested writes or relations). The store falls back on the first refusal and remembers it, so no existing setup breaks.
  
  Behaviour change: `auth.register` resolves before the verification mail is handed to the mailer and before the sign-up audit event is written. A test that reads the mail or the audit trail right after sign-up has to wait for them. A token store that fails while sign-up writes the verification code, or a user store that fails on the owner lookup, no longer fails the request. The error is logged as `Background task failed: verification mail` or `Background task failed: existing address notice`, and the user can ask for another verification mail.
- Updated dependencies [[`fb9f5d8`](https://github.com/noctcore/auth/commit/fb9f5d80dcdc515ff0e09b453c18136adddbd6ca), [`76717de`](https://github.com/noctcore/auth/commit/76717de578fbd4f83973dcf544acafeb1d5c9dad), [`5b79f16`](https://github.com/noctcore/auth/commit/5b79f16f9a597db92131f6684114c9f872cac4f5), [`c09f611`](https://github.com/noctcore/auth/commit/c09f611bc86253f33220e6d6ace54743de5cc1af), [`57440a0`](https://github.com/noctcore/auth/commit/57440a046b8f63cbca56f273ac611a8d6d391ebb), [`2ab09b7`](https://github.com/noctcore/auth/commit/2ab09b7b3769e14fbd72259138592df55a8bb3bb), [`e73f7a0`](https://github.com/noctcore/auth/commit/e73f7a0096808eb2fa9f705fe6c32983fb752e08)]:
  - @noctcore/auth@0.5.0

## 0.4.0

### Minor Changes

- [#59](https://github.com/noctcore/auth/pull/59) [`a78168e`](https://github.com/noctcore/auth/commit/a78168e668f7add8256d44596bd29a6455f61dd1) Thanks [@Shironex](https://github.com/Shironex)! - Add stores for the two-factor plugin: `RedisTwoFactorStore` in `@noctcore/auth-redis` and `PrismaTwoFactorStore` in `@noctcore/auth-prisma`. The Prisma store needs the four new models in `prisma/auth.prisma` (`AuthTwoFactor`, `AuthRecoveryCodes`, `AuthTrustedDevice`, `AuthStepUp`). Both pass `twoFactorStoreConformance`. `redisStores()` is unchanged; construct `RedisTwoFactorStore` yourself.

### Patch Changes

- Updated dependencies [[`a78168e`](https://github.com/noctcore/auth/commit/a78168e668f7add8256d44596bd29a6455f61dd1)]:
  - @noctcore/auth@0.4.0

## 0.3.0

### Patch Changes

- Updated dependencies [[`ceaae4c`](https://github.com/noctcore/auth/commit/ceaae4c11e265c833e34375e829cf34205cb07a5)]:
  - @noctcore/auth@0.3.0

## 0.2.0

### Minor Changes

- [#47](https://github.com/noctcore/auth/pull/47) [`fe2e067`](https://github.com/noctcore/auth/commit/fe2e06730b09f54d2a06ea2d573ebfb977a8f5ae) Thanks [@Shironex](https://github.com/Shironex)! - **Warning:** early 0.x releases are not meant for production apps yet. The API may have breaking changes between minor versions until 1.0.
  
  First release of the packages. `@noctcore/auth` is the framework-free core (sessions, flows, throttling, store interfaces and conformance suite), `@noctcore/auth-redis` and `@noctcore/auth-prisma` are the store adapters, and this release includes the first hardening pass: an attack suite, a coverage gate, and property and mutation tests.

- [#7](https://github.com/noctcore/auth/pull/7) [`59e3c5a`](https://github.com/noctcore/auth/commit/59e3c5a50eef7e063e3d239e1771f945cefcf4d7) Thanks [@Shironex](https://github.com/Shironex)! - Add `PrismaUserStore`, `PrismaTokenStore` and `prismaStores` for Prisma 7, typed against your client's model delegates, with configurable user columns, soft deletion, extra columns and a richer user type. Ships the `AuthToken` model in `prisma/auth.prisma`. Both stores pass the conformance suite on PostgreSQL.

### Patch Changes

- Updated dependencies [[`e61e894`](https://github.com/noctcore/auth/commit/e61e8945482bd23b4e432ced58145e09acdb973f), [`9305ef5`](https://github.com/noctcore/auth/commit/9305ef5548bc3ca5d10b058ece12795bcc44a89d), [`cdeddbf`](https://github.com/noctcore/auth/commit/cdeddbf146dc664734e8f52a49f53bae614529c1), [`f138781`](https://github.com/noctcore/auth/commit/f138781408c66595004a5ae7e3e8ac3fa5de9c90), [`a222dc2`](https://github.com/noctcore/auth/commit/a222dc29c9134b286d8acb16b13b66da249a7ff6), [`7ca4a52`](https://github.com/noctcore/auth/commit/7ca4a522899e5802058de35e8887c9201b91c378), [`fe2e067`](https://github.com/noctcore/auth/commit/fe2e06730b09f54d2a06ea2d573ebfb977a8f5ae)]:
  - @noctcore/auth@0.2.0
