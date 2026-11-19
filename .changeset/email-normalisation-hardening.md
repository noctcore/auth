---
'@noctcore/auth': minor
---

Hardens email normalisation after the 0.6 review.

- Every policy now refuses the same characters: whitespace, control characters and every RFC 5322 special an address parser acts on besides the one `@`: `,` `;` `:` `<` `>` `(` `)` `"` `\` `[` `]`. This applies to the built-in `standard`, `ascii` and `unicode` policies and to a custom normaliser's output, so an accepted address is never a recipient list, group syntax, a comment the parser strips, a quoted local part or a domain literal.
- Breaking for custom normalisers: one that passes a quoted local part through now fails the startup check (`"quoted"@example.com` is in the startup sample). Return `null` for an address with any of these characters.
- Upgrade note: a stored address with any of these characters (possible before under `standard` and `ascii`) can no longer sign in by address. Find such rows (`WHERE email ~ '[],;:<>()"\\[]'` in PostgreSQL) and rewrite them.
- The `unicode` policy takes a domain only when it is a host name: a port, path, query, fragment, credentials or percent escape (`example.com:25`, `evil.com/x`, `ex%41mple.com`) is refused, an ASCII domain must come back from the URL parser unchanged (so `127.1` is refused), and every label of its ASCII (punycode) form must be letters, digits and hyphens, not starting or ending with a hyphen, at most 63 long (so `example.com(x)` and `exa_mple.com` are refused).
- The `unicode` policy refuses an input longer than 1016 characters before any Unicode normalisation; the 254-byte limit still applies to the result.
- A custom normaliser that throws on the startup check for distinct mailboxes now fails `createAuth` with `AuthConfigError` (the original error as `cause`), like every other startup check.
- When the user store returns a row whose stored email is not exactly the normalised address, the core still treats it as not found and now logs a warning with the user id, never the address, so rows written in another spelling show up in the logs. Behind a case- or accent-insensitive collation the warning repeats on every lookup of such a row and can be noisy until the rows are rewritten.
