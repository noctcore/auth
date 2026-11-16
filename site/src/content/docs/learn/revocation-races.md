---
title: Revocation races and the epoch fence
description: How a per-user counter makes revoke-all safe against concurrent logins and crashes.
---

## What goes wrong

Changing a password should end every other session. The obvious code lists the user's sessions and deletes them. That has two holes:

1. **A concurrent login.** A login reads the stored password hash, then verifies the credential, then mints a session. If a password change commits and revokes in the middle, the login can finish after the cleanup ran, and the attacker who knew the old password ends up with a live session.
2. **A crash.** If the process dies after the password changed but before every session was deleted, the leftovers stay valid.

Deleting what you can find is not enough, because the session you cannot find yet (still being minted) or cannot reach (the cleanup never ran) survives.

## The rule: an epoch fence

Each user has a counter, the epoch.

1. **Read before checking.** A login reads the user's epoch before it checks the credential and stamps that value into the session it creates.
2. **Increment first.** Revoke-all increments the epoch first, and only then deletes the sessions it can find.
3. **Validate against the counter.** Validation rejects any session whose stamped epoch differs from the user's current epoch.
4. **Re-read at mint.** When the login mints its session it re-reads the epoch. On a mismatch it rolls the new session back.

## Why it holds

- A login that read the old password hash while a password change was committing read the epoch before the increment. Either the mint sees the new epoch and rolls back, or the session is stamped with the old epoch and validation rejects it. No order of events yields a live session.
- A crash between the increment and the cleanup leaves old sessions in the store, but each carries a stale epoch, so they are invalid rather than valid. Cleanup becomes housekeeping, not a security step.

The counter is the source of truth; deleting sessions only reclaims space.

## Further reading

[Auth sessions](https://auth.pilcrowonpaper.com/auth-sessions) in Pilcrow's auth guide, on tying a session to one authentication event.

## Related

[Sessions and expiry](/auth/learn/sessions-and-expiry/) covers the token and its expiry.
