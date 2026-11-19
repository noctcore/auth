---
'@noctcore/auth': patch
---

Two-factor enforcement is tidier. `sweepUnenrolled` reads the factor, the user and the policy again right before it revokes a user's sessions, so a user who enrolled (or whose rule changed) during the sweep is no longer signed out. `status` asks a custom `enforcement` function once and derives `required` and `enforcement` from that one answer. The tenant policy example in the Build guide now expires its cache entries and bounds its size.
