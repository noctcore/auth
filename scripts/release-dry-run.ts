/**
 * The release workflow's publish step, in dry-run form.
 *
 * Real publishing waits until the owner has registered an npm trusted
 * publisher for every package name (npm only lets you configure one on a
 * package that exists). Until then the workflow runs this instead of
 * `changeset publish`: it builds, then asks npm what each public package would
 * publish, without contacting the registry for a write.
 *
 * It prints no "New tag:" lines, so changesets/action creates no tags and no
 * GitHub releases on a dry run.
 *
 * To switch to real publishing, set the workflow's `publish-script` to
 * `bunx changeset publish` (see the comment in .github/workflows/release.yml).
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const PACKAGES = join(ROOT, 'packages');

function run(command: string, args: readonly string[], cwd: string): void {
  const result = spawnSync(command, args, {
    cwd,
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });

  if (result.status === 0) return;

  console.error(`${command} ${args.join(' ')} failed in ${cwd}`);
  process.exit(result.status ?? 1);
}

run(process.execPath, ['run', 'build'], ROOT);

for (const dir of readdirSync(PACKAGES).sort()) {
  const cwd = join(PACKAGES, dir);

  const manifest = JSON.parse(readFileSync(join(cwd, 'package.json'), 'utf8')) as {
    name: string;
    version: string;
    private?: boolean;
  };

  if (manifest.private === true) continue;

  console.log(`\n=== ${manifest.name}@${manifest.version} (dry run)`);
  run('npm', ['publish', '--dry-run', '--provenance=false', '--access', 'public'], cwd);
}
