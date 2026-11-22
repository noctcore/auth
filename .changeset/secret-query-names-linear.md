---
'@noctcore/auth-trpc': minor
---

`assertNoSecretQueries` catches more secret names in a query's input, and splits a key into words in linear time.

New names: run-together forms behind a lead the camelCase form already flagged (`pincode`, `newpin`, `oldpin`, `currentpin`, `twofactorcode`, `2facode`, `hotpcode`), `hotp` and `pwd` as words, `credential`, `jwt`, `bearer` and `authorization` as the last word of a key (`credentials`, `accessJwt`; `credentialId`, `jwtIssuer` and `authorizationUrl` still pass), and the key pairs `privateKey`, `accessKey`, `signingKey` and `encryptionKey` beside `apiKey`, written as two words or one (`apikeys` used to slip through). `publicKey`, `keyboard`, `sessionId`, `pass` and `signature` still pass: the first two are no secret, and the last three are as often a plain identifier, a flag or a value meant for a URL.

The word split used a regular expression that backtracked over every run of capitals, about 5 s on a 100,000 character all-caps key. It is now one pass over the key and gives the same words on every input.

Behaviour change: a router whose queries take one of these names in their input now fails `assertNoSecretQueries` where it used to pass. That includes a postal `pincode` field and an `accessKeyId`. Make the procedure a mutation, or list its path in `allow` once checked by hand.
