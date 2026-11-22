---
'@noctcore/auth': patch
---

`clientIp` now treats an empty socket address (`remoteAddress: ''`) as missing in every branch: with 0 hops, with a hop count and no usable header entry, and with a proxy list. It used to return `''`, which reached rate-limit keys and audit rows as an empty IP; it now returns undefined, which the NestJS and tRPC adapters turn into `unknown`, as for a request with no socket address. Node and Bun do not report an empty peer in practice.
