---
'@noctcore/auth': patch
---

New `adoptLegacySessions(store, { take, maxTtl })` wraps a session store so an app switching to the package keeps its users signed in. A session the store does not hold is taken once from the app's own store (removed as it is read), written in the package's format and served from the package's store from then on. The adopted session carries revocation epoch 0, so a password change or sign-out everywhere since the switch refuses an old session presented later; its expiry never passes the old one or `maxTtl` after its creation; expired, future-dated and malformed records are dropped. See "Switching from your own sessions" in the store adapter guide.
