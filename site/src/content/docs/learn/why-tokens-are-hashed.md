---
title: Why tokens are hashed
description: What a leaked store or log gives an attacker, a fast hash for random tokens versus a keyed or slow one for short secrets, and what hashing at rest does not protect.
---

## What goes wrong

Secrets leak from places other than the cookie: a database dump, a Redis snapshot, a backup, a read replica someone can query, a log line that printed a row. If the store holds the tokens themselves, every such leak is a list of live sessions and unused reset links, ready to use without going near the login form. A leak is also quiet: nothing in the app notices that a copy of the table exists somewhere else.

## The rule

**Store the hash, never the token.** The session store key is the SHA-256 of the session token. Email verification and reset links, the reset ticket, email change and revert links, the two-factor plugin's login challenges and its trusted-device tokens are stored the same way. Whoever holds the store holds hashes, and to use one they would need a token that hashes to it.

**A fast hash is enough for a random token, not for a short secret.** A password gets a slow, salted hash because people choose from a small, predictable set, which an attacker can try at billions of fast hashes a second (see [Passwords](/auth/learn/passwords/)). A 32-byte random token has no such set: SHA-256 is fast, but there are far too many tokens to try, so a slow hash would add cost and no safety. A code a person types is the opposite case: with 8 digits by default, hashing every possible code takes moments, so a plain hash would be reversed straight from a leaked table. Codes are therefore stored as an HMAC-SHA-256 under a key derived from the server secret, over the purpose, the user id and the code. Without the secret the table cannot be searched, and a row copied onto another account or purpose matches nothing. Recovery codes and invitation tokens are stored as HMACs too, each under its own derived key.

**Compare without leaking.** A code's HMAC is compared with the stored one in constant time. A token is never compared at all: its hash is the key it is looked up by. On Node, Bun and Deno the comparison runs on `crypto.timingSafeEqual`, found at runtime so that bundles for other runtimes never import `node:crypto`; everywhere else it runs on a JavaScript loop that never stops early. Both answer the same. Two values of different lengths are unequal straight away, which reveals only that the lengths differ, and every comparison is between digests of a fixed length (secrets of any length, such as CSRF tokens, are hashed first).

**What hashing at rest does not protect.**

- *A token in use.* Whoever reads the cookie in the browser, a request body, a URL or a log of requests has the token itself, not its hash. Put link tokens in the URL path or fragment and send `Referrer-Policy: no-referrer`, keep secrets out of query strings (the tRPC adapter refuses a query whose input names one, attack A029), and never log request bodies of the auth routes.
- *Write access to the store.* An attacker who can write can insert a session row for a token they made, reset counters or change a password hash. The store is inside the trust boundary: protect it with network isolation, credentials and TLS.
- *The server secret.* With the secret and a leaked table, the code HMACs can be searched again, which is why codes also expire within minutes and run out of attempts. Rotating the secret voids outstanding codes, recovery codes, pending invitations and the lockout's device cookies. It never voids sessions, links or the two-factor plugin's trusted-device tokens, whose hashes use no key.
- *Hashes in your own responses.* The session id an app lists and revokes is the token's hash, which is not a credential, but a store row has other fields worth keeping private. The tRPC adapter's output schemas strip everything they do not name (attack A030).

## Where the package and the guide differ

The guide hashes its session secret with SHA-256 before storage and compares the hash in constant time, next to a separate session id. The package hashes the same way but uses the hash itself as the lookup key, so no comparison is needed and no separate id exists. It also stores short codes, which the guide's sessions page does not cover, as keyed HMACs instead of plain hashes.

## Further reading

- [Sessions](https://auth.pilcrowonpaper.com/sessions) in Pilcrow's auth guide.
- [Entropy and tokens](/auth/learn/entropy-and-tokens/) for why a token has enough bits to need no slow hash.
- Attack tests: [A017, replaying secrets from a leaked store](https://github.com/noctcore/auth/blob/main/packages/auth/tests/attacks/A017-leaked-store-replay.test.ts), [A029, a secret in a tRPC query](https://github.com/noctcore/auth/blob/main/packages/auth-trpc/tests/attacks/A029-secret-in-a-query.test.ts) [A030, a hash field in a tRPC output](https://github.com/noctcore/auth/blob/main/packages/auth-trpc/tests/attacks/A030-hash-field-in-an-output.test.ts) and [A078, learning a secret from how long its comparison takes](https://github.com/noctcore/auth/blob/main/packages/auth/tests/attacks/A078-secret-comparison-timing.test.ts).
