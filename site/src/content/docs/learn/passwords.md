---
title: Passwords
description: Why passwords get a slow, salted hash, what the policy checks and what it leaves alone, and how hashes upgrade themselves.
---

## What goes wrong

People reuse passwords. A table of stored passwords, or of fast hashes of them, is a list of credentials for other sites too: a fast hash like SHA-256 can be tried billions of times a second on a GPU, and most real passwords fall to that within hours. On the other side, the server pays for every login, so a hash that is slow for the attacker is slow for you as well.

## The rule

**Hash with Argon2id, salted, at a cost you have measured.** Argon2id needs a block of memory per hash, which is what makes GPU and custom hardware attacks expensive. Each hash gets its own random salt, so equal passwords produce different hashes and precomputed tables are useless. The defaults are 19 MiB of memory, 3 passes and 1 lane: the memory figure is OWASP's floor, the pass count is the auth guide's. Raise the memory on a box that can afford it, not the passes or lanes.

**Hashes upgrade themselves.** Every login that succeeds checks whether the stored hash was made with the current parameters. If not, the password the user just typed is hashed again and stored, as a compare-and-set on the old hash: if a password change or reset lands while the new hash is being computed, the upgrade is dropped instead of bringing the old password back. Raising the cost later, or adopting hashes made by an older app, needs no migration and no reset.

**Check length, not composition.** A password must be 12 to 256 characters, counted as Unicode code points after NFC normalisation (so the same password typed on two keyboards hashes the same). There are no "one digit, one symbol" rules: they push people towards predictable patterns without adding much strength. Instead, a new password is checked against known breaches (next section).

**Refuse, never repair.** Apart from NFC normalisation, input is never trimmed or rewritten. A rejected password gets a reason the user can act on: `weak_password`, `password_too_long` or `breached_password`.

**Ask whether it has leaked.** The breach check sends only the first five characters of the password's SHA-1 to the Pwned Passwords range API and compares the rest locally, so the password never leaves the server. If the service is down, the check fails open: the password is accepted, a warning is logged and the `auth_breach_check{verdict="unavailable"}` metric goes up, so an outage is visible without blocking sign-ups.

**Bound the work.** Every door that hashes a password has a rate limit, and an input longer than the policy's maximum is never handed to the hasher at all.

## Where the package and the guide differ

- **Minimum length.** The guide suggests 8 or 10. The package uses 12, from the original production implementation, and refuses a configured minimum below 8.
- **Maximum length.** The guide suggests 50 to 100. The package allows 256, so long passphrases and generated passwords fit; the per-door limits already bound the hashing cost.
- **Character set.** The guide is comfortable limiting passwords to printable ASCII. The package accepts any Unicode and normalises it with NFC, which the guide names as the requirement when Unicode is allowed.
- **Passes.** OWASP's floor is 2 passes at 19 MiB, the guide's is 3 passes at 16 MiB. The package takes the stricter value of each.

## Further reading

- [Passwords](https://auth.pilcrowonpaper.com/passwords) and [Argon2](https://auth.pilcrowonpaper.com/argon2) in Pilcrow's auth guide.
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
