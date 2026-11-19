---
'@noctcore/auth': minor
---

The `standard` (default) and `ascii` email policies take only a host name as the domain, as `unicode` does: letters, digits and inner hyphens per label (at most 63 characters), no empty label, and a last label that is not all digits. They used to check only for one inner dot, so `a@exa_mple.com`, `a@-example.com`, `a@example..com`, `a@127.0.0.1` and `a@127.1` were accepted; they are now answered `invalid_email`.

Behaviour change: a stored address whose domain is not a host name (an IPv4 address, an underscore or another character outside a host name, an empty label, a label that starts or ends with a hyphen or is longer than 63) can no longer sign in, reset or be found by address, and a pending invitation to it cannot be accepted. An outstanding email change or verification token that names such an address can no longer be redeemed either: the flows normalise the address again when the token is used and refuse it (they fail closed), so the user has to start the change or request a new mail with a valid address. Find such rows before upgrading and rewrite or remove them. In PostgreSQL, on your user table and on `AuthInvitation`:

```sql
SELECT id, email FROM users -- your user table
WHERE split_part(email, '@', 2) !~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
   OR split_part(email, '@', 2) ~ '\.[0-9]+$';

SELECT id, email FROM "AuthInvitation"
WHERE split_part(email, '@', 2) !~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
   OR split_part(email, '@', 2) ~ '\.[0-9]+$';
```

On another store, look for the rows where `auth.normalizeEmail(email)` is not exactly the stored email, which finds these too (see the configuration reference).

Upgrade note for the `unicode` policy: what it accepts depends on the runtime's URL parser and Unicode tables (Node, Bun, an edge runtime), so uniqueness holds on one runtime, but an address stored under one runtime can be refused after a runtime upgrade that remaps one of its characters.

Docs: `adoptLegacySessions` signals a lost adoption race on the store it returns, so pass that result directly to `createAuth`; a store of your own that wraps it hides the signal and the user is signed out again. Wrap the package's store before `adoptLegacySessions` instead.
