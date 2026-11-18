# Vision

@noctcore/auth is authentication for TypeScript servers in the spirit of Lucia: small modules you can read in an afternoon, each tied to the attack or mistake it exists for. A Bun workspace of five packages (`auth`, `auth-nestjs`, `auth-prisma`, `auth-redis`, `auth-trpc`), all sharing one version. It is early development (0.x previews, not for production yet).

## Goals
- Migrate Aldra's authentication onto this package (issues #23 and #25); the owner decides when.
- Continue 0.x minors, one per milestone with a changesets changelog, tag and GitHub release (0.5.0 "identity" shipped 2026-11-17), then 1.0.0-rc releases during a four-week soak, then 1.0.0.
- Follow-up issues: CSRF cookies fixed at SameSite=Lax for desktop shells, refuse a fixed SameSite=none with `secure:false` at startup, document the reset quota and invitation behaviour on secret rotation.
- Clear the OpenSSF Scorecard items that need the owner (branch protection, code review, CII badge).

## Target users
- Developers of NestJS, tRPC or plain TypeScript servers who want auditable auth, with Redis or Prisma stores.
- The owner's apps, Aldra first.

## Principles
- Workflow: branch and PR for all work; agents do not merge (no exemption row exists for this repo, so the owner's default applies; confirm if told otherwise). Only the owner merges the changesets "Version Packages" PR, which publishes to npm. Never run `npm publish` or push release tags by hand.
- Commits are `type(scope): lowercase summary`, one logical change each, with the package or area as scope (`auth`, `auth-nestjs`, `auth-prisma`, `docs(site)`, `chore(release)`). No AI attribution, no em or en dashes in code, comments or docs.
- Package manager is Bun (`bun@1.4.2`, `bun.lock`).
- Every source module starts with a comment naming the attack or mistake it exists for. Flows return `AuthResult` values, never throw for user errors and never touch HTTP. A public refusal code never reveals account state.
- Every security fix adds a numbered attack test that fails before the fix (`packages/auth/tests/attacks/`, indexed in `ATTACKS.md`). Attack tests are never deleted and numbers are never reused.
- Stricter default wins where guidance disagrees; every default has its reason in the source.
- Each PR to a published package carries a changeset (`bun run changeset`, or `--empty`). A lint exception is a scoped `files` override with a reason, never an inline disable.

## Out of scope
- HTTP routes or endpoints: plugins add flows, not endpoints.
- Provider or OAuth login flows beyond what the milestones add.
- Production-readiness claims before 1.0.

## Quality bar
- `bun run format:check`, `bun run typecheck`, `bun run lint` (after a build), `bun run test` (unit, attack and property tests with coverage thresholds), `bun run check:api`, `bun run check:package`, `bun run check:deps`, `bun run check:workflows`.
- `bun run services:up && bun run test:integration` for Redis and Postgres conformance. Public API changes need `bun run api:update` and the new `api/*.api.txt` reports.
- Scheduled: nightly fuzz, weekly mutation (Stryker), Scorecard target 7.5.

## Protected areas
- `packages/auth/src/crypto/**`
- `packages/auth/src/session/**`
- `packages/auth/src/tokens/**`
- `packages/auth/src/password/**`
- `packages/auth/tests/attacks/**`
- `api/**`
- `docs/THREAT_MODEL.md`
- `.changeset/config.json`
- `.github/workflows/**`
- `RELEASING.md`
- `SECURITY.md`
- auth
- secrets
- release
- licensing

## Agent defaults
- Model: Sonnet for docs, notes, plans, decision records, reviews of small diffs, mechanical edits and searches; Opus only for hard code (new modules, security, cross-package changes, debugging) and say why in the brief.
- Effort: `medium` by default, `low` for docs, notes and mechanical edits, `high` only for a hard design or debugging task, with the reason in the brief.
- At most 2 agents running at once for this project; queue the rest.
- One issue or PR per agent; end the session when its PR is open or its report is in, and start a fresh agent for the next task instead of reusing a long session.
