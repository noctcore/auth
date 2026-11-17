---
'@noctcore/auth': patch
---

The Pwned Passwords breach check now upper-cases response lines in ASCII only before checking their format. Before, `toUpperCase()` folded some non-ASCII characters into ASCII ones (the ligature U+FB00 became "FF"), so a malformed or tampered line could pass the format check and count as a breach instead of making the check report "unavailable".
