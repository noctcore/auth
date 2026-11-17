---
'@noctcore/auth': patch
---

`verifyRequestOrigin` and `verifyFetchSite` now upper-case the request method in ASCII only before checking for GET, HEAD and OPTIONS. Before, `toUpperCase()` folded some non-ASCII letters into ASCII ones, so a method such as `OPTION` followed by a long s was treated as safe and skipped the check. Browsers and Node's HTTP parser refuse such methods, so this was not reachable from another site.
