---
'@noctcore/auth': patch
---

The per-user session cap never evicts the session the mint just wrote. The eviction used to sort every live session by `createdAt` and cut from the old end, so a new session whose creation time tied an older one (same millisecond, with the store's listing order deciding the tie) or came before it (an instance whose clock is behind) could be deleted by its own mint: the sign-in succeeded with a dead token, listed its own id in `evicted` and fired `onSessionsRevoked('evicted')` for it.

When a cap is set, a mint now reads the user's sessions once before it writes (one extra `listByUser` per mint). After the write it evicts, oldest first by `createdAt` and then by id, only sessions that were stored before it began or that sort before it, and never itself. A tie or a lagging clock still evicts the older session, and of two sign-ins racing at a cap of one exactly one is left. Two narrow cases remain: a sign-in that stalls before its write while a later one finishes can leave one session over the cap until the next sign-in, and sign-ins on instances whose clocks disagree can evict each other. The session store conformance suite gains two cases: a mint at a cap of one at the same instant keeps its own session, and two mints racing at a cap of one leave exactly one session and report each eviction once.
