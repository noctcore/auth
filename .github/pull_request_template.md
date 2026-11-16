<!--
Title: a conventional commit with a scope, for example `fix(auth): keep the epoch on session rotation`.
Keep this short. CONTRIBUTING.md has the long version.
-->

## Summary

<!-- What changes and why, in one or two sentences. For a security property: the attack it stops and what it leaves alone. -->

Closes #

## Checklist

- [ ] A changeset in `.changeset/` (`bun run changeset`), written for a consumer reading the changelog. A weakened default or a removed check is major; a stricter default that may log users out or refuse old input is minor with a "Behaviour change" note. Changes that release nothing use `bun run changeset --empty`.
- [ ] `bun run build && bun run format:check && bun run typecheck && bun run lint && bun run test` pass locally
- [ ] `bun run check:package && bun run check:api` pass; if the public API changed on purpose, `bun run api:update` ran and the new reports in `api/` are committed
- [ ] Store or adapter changes: `bun run services:up && bun run test:integration` pass
- [ ] A new source module starts with a comment that says which attack or mistake it exists for
- [ ] A refusal's public `code` never reveals account state; flows return `AuthResult` values and never touch HTTP
- [ ] No secrets, real hostnames, IPs or email addresses in code, fixtures or docs (use `example.com` and documentation ranges)
- [ ] Commits are small `type(scope): lowercase summary` commits, with no em or en dashes and no AI attribution lines

## Test plan

<!-- Commands run, cases covered, what a reviewer can try. -->
