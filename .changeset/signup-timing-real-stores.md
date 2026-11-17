---
'@noctcore/auth': minor
'@noctcore/auth-prisma': patch
---

Sign-up no longer waits on the work that differs between a taken and a new address. The answer waits on the door limit, the password hash and one insert; after that, a taken address's owner lookup, `account-exists` mail and `register.existing` audit event, and a new address's `register.created` audit event, verification token and `verify-email` mail, run in the background. On Postgres and Redis the taken path used to answer a few milliseconds slower, enough for `bun run bench:timing:stores` to tell the paths apart.

The Prisma user store inserts with `skipDuplicates` through `createManyAndReturn` when the delegate has it (PostgreSQL, CockroachDB, SQLite), so a taken address is a skipped insert instead of a failed statement. On PostgreSQL through `@prisma/adapter-pg`, a failed statement made the next query about 3 ms slower. Delegates without `createManyAndReturn` keep the old insert, where a unique violation answers `null`. With `createManyAndReturn`, `createData` and `select` must name plain columns, because it accepts no nested writes.

Behaviour change: `auth.register` resolves before the verification mail is handed to the mailer and before the sign-up audit event is written. A test that reads the mail or the audit trail right after sign-up has to wait for them. A token store that fails while sign-up writes the verification code, or a user store that fails on the owner lookup, no longer fails the request. The error is logged as `Background task failed: verification mail` or `Background task failed: existing address notice`, and the user can ask for another verification mail.
