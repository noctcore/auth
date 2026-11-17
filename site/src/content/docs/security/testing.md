---
title: How this library is tested
description: Every gate a change to the library must pass, what each one catches, and how to run it yourself.
---

Authentication code fails quietly: a missing check still returns 200. So the library is tested from several angles. Most of them are required checks: a pull request cannot merge until they pass, and none of them is allowed to fail and let the run pass. Three run on a schedule instead and do not block a merge: the nightly property run, the weekly mutation run and OpenSSF Scorecard. A failure there is a failed run on `main` to fix.

## Unit tests and coverage

Every flow and primitive runs against in-memory fakes of the stores, the mailer and the clock, so a test can freeze time, race two requests or make a store fail on cue. `bun run test` runs them with coverage, and the run fails under the thresholds in `packages/auth/vitest.config.ts`:

- the modules that decide who is signed in (crypto, tokens, session, throttle, password) are held at 100 percent of lines, branches and functions;
- the HTTP helpers sit just under 100 (99 percent of branches), and the flows at 99 percent of lines and 95 percent of branches;
- the Redis and Prisma adapters have their own thresholds, measured against the real servers.

Nothing is excluded from coverage. One branch is left uncovered on purpose: a fallback the type checker requires after `split` in the client IP masking, which no input can reach. The config names it, and the thresholds for `http` sit just under 100 because of it.

## The attack suite

`packages/auth/tests/attacks/` holds one numbered test file per attack (an adapter that adds attack surface, such as `@noctcore/auth-nestjs`, keeps its own in its `tests/attacks/` folder, numbered in the same sequence): `A001` brute force by parallel guesses, `A004` enumeration by timing, `A012` account pre-hijacking, and so on. The [index](https://github.com/noctcore/auth/blob/main/packages/auth/tests/attacks/ATTACKS.md) maps each one to its Learn page and the module that stops it, and the [threat model](/auth/security/threat-model/) maps the attacks to the defenses. An attack test is never deleted and a number is never reused, and every security fix adds one that fails before the fix.

## Timing

A timing leak is checked by counting work, not by measuring the clock, so the check cannot flake on a busy CI machine. Attack `A004` records every call each flow makes through a store port, and every password verify. It then requires:

- at login, the same sequence of calls and one verify for a known and an unknown address, whether the account is open or locked. A locked account makes fewer counter calls than an open one (the gate stops before spending budgets), the same for known and unknown addresses, and the test pins every other call;
- at the password reset request, the same sequence for a known and an unknown address;
- at sign-up, one hash, one mail and the same number of store round trips for a taken and a new address. The calls are not identical: a taken address looks the owner up where a new account writes its verification token. The test pins both sequences, so any other drift fails.

Attack `A023` hands every flow that mails a mailer that never settles and requires each answer anyway, on Vitest's fake timers rather than the wall clock: no flow waits for delivery.

`bun run bench:timing` also measures the wall clock with the real Argon2id hasher. It compares the same pairs over shuffled, seeded samples and reports medians and Welch's t. It is for reading, not gating. The in-memory stores make a store call nearly free, so `bun run bench:timing:stores` times the sign-up pair again on Postgres and Redis (after `services:up` and a build), where each call is a round trip.

A lint rule pushes secret comparisons onto the constant-time helpers in `crypto/hash.ts`. It matches by name and by the forms listed below, so it narrows the ways to slip rather than proving there are none: a secret under an unrelated name, or read some other way (a template-literal key, a computed method name, a `switch`, `startsWith` or `includes`), is not caught, and review still has to look. In library code it refuses:

- `==`, `===`, `!=` or `!==` where either side is named like a hash, token, code, secret, digest, MAC or signature, however it is read: `tokenHash`, `row.tokenHash`, `row?.tokenHash`, `rec['passwordHash']`, or wrapped in `as`, `satisfies` or `!`. A comparison with a literal, `undefined` or a `typeof` is a shape check and is allowed;
- `.equals()`, `Object.is()` and `localeCompare()` on such a value;
- `Buffer.compare` and `timingSafeEqual`;
- importing the constant-time primitive outside `crypto/hash.ts`.

A secret kept under an unrelated name is not caught: the rule narrows the ways to slip, and review covers the rest. A fixture test proves each form above is caught.

## Property tests

[fast-check](https://fast-check.dev/) generates inputs for the parsers and checks: cookies, CSRF tokens and the Origin check, device cookies, client IPs behind proxies, email normalisation, the password policy and durations. They run in the normal suite with a fixed seed. Nightly, outside the required checks, they run with a new seed and a hundred times more cases. A failure prints its seed, and `FC_SEED=<seed> bunx vitest run tests/property` replays it.

## Mutation testing

Coverage says a line ran, not that a test would notice it breaking. [Stryker](https://stryker-mutator.io/) changes one operator, condition or literal at a time in crypto, tokens, session, throttle, the CSRF checks and the client IP parser, and reruns the tests. The run fails if the share of changes the tests catch drops under the threshold in `packages/auth/stryker.config.mjs` (96 percent; measured 97). The few changes no test can tell apart from the original are listed there, each with its reason. It runs weekly and on demand, not on pull requests, so it does not block a merge; run it locally with `bun run test:mutation`.

## Real backends

The Redis and Prisma adapters pass the same conformance suite any adapter must pass, against real Redis and Postgres in Docker:

- tokens are consumed once under fifty concurrent callers;
- a revoked session never comes back;
- every counter key expires.

The example app runs end to end against both. CI sets `AUTH_REQUIRE_SERVICES=1`, so these suites can never skip there.

## Types, lint and the public API

- **TypeScript** runs with `strict`, `exactOptionalPropertyTypes`, `noUncheckedIndexedAccess` and `noPropertyAccessFromIndexSignature`.
- **ESLint** uses type information. It enforces the layering between modules, refuses `any` in published source (one documented exception for Prisma's generated delegates), and refuses a promise left floating.
- **The public API** of every entry point is compared with the reports in `api/` on every pull request, so a refactor cannot change what consumers import by accident.
- **The packed tarballs** are checked for the files and exports they must contain.

## The supply chain

- **CodeQL** scans every pull request with the extended security queries.
- **Dependency review** refuses a pull request that adds a dependency with a high-severity advisory or a licence outside the allowlist.
- **Runtime dependencies** must match an allowlist that fails closed: a new one needs a reviewed change to `scripts/runtime-dependencies.json`.
- **Workflows**: every action is pinned to a commit SHA with its version beside it, and every workflow declares least-privilege permissions; a script checks both.
- **OpenSSF Scorecard** grades the repository weekly and on every push to `main`; it does not gate pull requests. The target is 7.5 out of 10. The score is held back mainly by a single maintainer (code review and contributor checks), which is expected for a project this young.

## Running it yourself

```sh
bun install && bun run build
bun run format:check && bun run typecheck && bun run lint
bun run test                    # unit, attack and property tests, with coverage
bun run check:api && bun run check:package
bun run services:up && bun run test:integration
bun run test:mutation           # about two minutes
bun run bench:timing            # wall clock, not a gate
bun run bench:timing:stores     # sign-up on Postgres and Redis, not a gate
```

[CONTRIBUTING.md](https://github.com/noctcore/auth/blob/main/CONTRIBUTING.md) lists every gate with the job that runs it, and which ones are required to merge.
