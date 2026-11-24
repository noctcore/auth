---
'@noctcore/auth': patch
'@noctcore/auth-prisma': patch
---

A password write that throws may still have committed (the connection dropped after the commit). `resetPassword` and `changePassword` now end every session in that case too, as after any write, before they write `password.reset_failed` or `password.change_failed` (reason `write_failed`) and rethrow. Ending the sessions when the write did not land costs a sign-in; keeping them when it did would keep an intruder in. After such a throw the account may have either password: tell the user to try the new one.

An async metrics port (`count: async () => ...`, which TypeScript accepts as `Metrics`) that rejects is now caught and logged as `Metrics port failed`, in the flows and in the background timer, instead of becoming an unhandled rejection that ends a Node process by default. A logger that throws while that failure is reported is ignored.

`PrismaUserStore` `writeWhere` now works out from the guard's shape which conditions match no row (`OR: []`, `in: []`) and carries that through `AND`, `OR`, `NOT`, `not`, `some`, `none`, `is` and `isNot`. Any condition that then matches every row is refused at boot, such as `{ NOT: { OR: [{ OR: [] }] } }`, `{ NOT: { closedAt: { in: [] } } }`, `{ m: { none: { OR: [] } } }`, `{ p: { isNot: { OR: [] } } }` or `{ closedAt: { notIn: [] } }`. So are `some` and `none` (or `is` and `isNot`) of one condition on one relation, on one key or split over an `OR`. The store does not know the model: a misplaced relation filter or an unknown column still fails on the first guarded write, and a to-one relation filtered without `is` reads as a column, so write `is: { ... }`.
