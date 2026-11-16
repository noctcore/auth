# Changesets

This folder holds [changesets](https://github.com/changesets/changesets): one Markdown file per pending
change, recording which packages bump and why. Add one with `bun run changeset` and commit it with the
change. Every `@noctcore/auth*` package is in one fixed group, so they always share a version.

A change that weakens a default or removes a check is `major`. A change that strengthens a default in a
way that can log users out or refuse old input is `minor`, with a "Behaviour change" paragraph. Fixes
are `patch`. See `SECURITY.md`.
