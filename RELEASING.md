# Releasing

Releases are made by the `release` workflow (`.github/workflows/release.yml`) with
[changesets](https://github.com/changesets/changesets). Publishing goes through npm trusted
publishing (GitHub OIDC), so there is no npm token anywhere, and every version carries provenance.

All packages share one version (`fixed` in `.changeset/config.json`): a release of one is a
release of all of them.

## The plan

Each milestone ships a 0.x minor with a changelog, a git tag and a GitHub release. After the last
milestone come release candidates during a soak, then 1.0.0. The first real release is 0.2.0.

## The flow

1. **Pull requests carry a changeset.** A PR that changes a published package runs
   `bun run changeset`; a PR that releases nothing runs `bun run changeset --empty`. The
   `changeset status` check enforces it.
2. **Merging to `main` opens or updates the "Version Packages" PR.** The workflow runs
   `changeset version` (through `bun run version-packages`), which bumps versions, updates the
   internal dependency pins and writes the CHANGELOGs, then refreshes `bun.lock`.
3. **Review the Version Packages PR.** Check the versions and the changelog text. Edit a changeset
   on `main` if the wording is wrong, and the PR updates itself.
4. **Merging the Version Packages PR publishes.** With no changesets pending, the workflow builds
   and tests, then runs `bun run release` (`changeset publish`). Each package that has a new
   version goes to npm with provenance, and the workflow pushes a `@noctcore/<name>@<version>` tag
   and creates a GitHub release for it.

The release job runs only on `main`: dispatching the workflow from any other branch does nothing, so
a manual dispatch is only for re-running a release from `main`.

Never run `npm publish` by hand and never push release tags by hand. If a run fails halfway,
re-run the failed workflow: `changeset publish` skips versions that already exist on npm.

## Owner-only steps

- Merge the Version Packages PR. Nothing else publishes.
- Register a trusted publisher on npmjs.com for every new package name (repository
  `noctcore/auth`, workflow `release.yml`) before its first release. npm only allows this on a
  package that exists, so a new name is first created from the npm website or with a placeholder
  version.
- Move dist-tags (see below), which needs an interactive npm login with 2FA.
- Consumers add `@noctcore/*` to their minimum-release-age exclusions so a security release can be
  adopted the same day.

## Release candidates

Before 1.0.0, a soak of release candidates uses changesets' prerelease mode. Do not enter it until
the last 0.x milestone is out.

```sh
bun run changeset pre enter rc     # writes .changeset/pre.json, commit it
```

While `pre.json` exists, each Version Packages PR produces `1.0.0-rc.0`, `1.0.0-rc.1` and so on,
and `changeset publish` publishes them under the `rc` dist-tag, never `latest`, so
`bun add @noctcore/auth` keeps resolving to the last stable version. Changesets refuses a custom
`--tag` in pre mode, so the dist-tag always equals the pre tag.

The soak plan names the `next` dist-tag. To have `next` point at the newest candidate as well,
run this after each candidate is published (it is an owner step, because trusted publishing only
covers `npm publish`):

```sh
npm dist-tag add @noctcore/auth@1.0.0-rc.1 next
npm dist-tag add @noctcore/auth-redis@1.0.0-rc.1 next
npm dist-tag add @noctcore/auth-prisma@1.0.0-rc.1 next
```

If you would rather not move tags by hand, enter pre mode with `bun run changeset pre enter next`
instead: the versions become `1.0.0-next.0` and so on, and the dist-tag is `next` with no extra step.

To ship 1.0.0 after the soak:

```sh
bun run changeset pre exit         # commit the change to pre.json
```

The next Version Packages PR then produces `1.0.0` and publishes it as `latest`.

## Checks before a release

`bun run check:package` (publint and arethetypeswrong) and `bun run release:dry-run` (build, then
`npm publish --dry-run` per package) show what would be published. The packages ship only `dist`,
`README.md` and, for `@noctcore/auth-prisma`, the `prisma` schema folder.
