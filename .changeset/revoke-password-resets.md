---
'@noctcore/auth': minor
---

New `auth.revokePasswordResets({ userId, meta? })`: voids the account's live reset links, and in code mode its codes and tickets, for a change your own code makes that must end a pending reset (an email change you run yourself, an admin moving the account to a new address, a support action). It touches no other token (a pending email change, a revert link and a verification link stay live), never mails, is safe to repeat, answers `{ revoked }` and writes the new `password.reset_revoked` audit event (`{ userId }`) only when it removed a live one.
