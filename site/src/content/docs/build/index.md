---
title: Build
description: Guides for wiring the library into an app.
---

Each guide builds on [Getting started](/auth/start/getting-started/), and its code is compiled with the site, so it matches the current API.

- [A Node server with Redis and Prisma](/auth/build/node-server/): configuration from the environment, trusted proxies, all three CSRF layers, email verification and password reset routes.
- [Mail into your templates and queue](/auth/build/mail/): one template per mail event, a queue in front of SMTP, and password reset jobs on your own worker.
- [Use with NestJS](/auth/build/nestjs/): the module, the guard order, CSRF before any guard, the trust-proxy rule and a compile test that pins the open routes.
- [Use with tRPC](/auth/build/trpc/): the session context on the Node and fetch adapters, guarded procedures, CSRF on mutations, cookies on rotation, safe error mapping and the checks to run in a test.
- [Writing a store adapter](/auth/build/store-adapter/): what each store must guarantee, and how to run the conformance suite from `@noctcore/auth/testing` against yours.
- [Two-factor](/auth/build/two-factor/): TOTP with recovery codes and trusted devices, a cipher for the secrets, the login challenge, step-up for your own sensitive actions, and moving existing TOTP users over.
- [Email change](/auth/build/email-change/): fresh authentication and the second factor to ask, a code to the new address, a revert link to the old one, and what each answer means for the routes.
- [Membership guards](/auth/build/membership/): changing roles and removing members without acting on yourself, without leaving an organisation with no admin, and with a demoted member signed out at once.
