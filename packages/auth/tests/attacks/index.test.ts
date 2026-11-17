// Keeps the attack suite and its index (ATTACKS.md) in step: every numbered
// file has a row and a header naming its attack, every row has a file, and
// the numbers run from A001 with no gaps, so a deleted attack test shows up as
// a hole instead of disappearing quietly.
//
// The suite is numbered across the repository: an adapter that adds attack
// surface keeps its attack tests in its own `tests/attacks/` folder (they need
// the framework, which this package must not depend on), and their rows link
// there from this index.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const DIR = new URL('./', import.meta.url);
const PACKAGES = new URL('../../../', DIR);
const FILE = /^(A\d{3})-[a-z0-9-]+\.test\.ts$/u;

/** Every attack file in the repository, by the path ATTACKS.md links it with. */
const files = new Map<string, URL>();

for (const pkg of readdirSync(PACKAGES).sort()) {
  const dir = new URL(`${pkg}/tests/attacks/`, PACKAGES);

  if (!existsSync(dir)) continue;

  const prefix = pkg === 'auth' ? '' : `../../../${pkg}/tests/attacks/`;

  for (const name of readdirSync(dir).filter((n) => FILE.test(n)))
    files.set(`${prefix}${name}`, new URL(name, dir));
}

const index = readFileSync(new URL('ATTACKS.md', DIR), 'utf8');

const rows = [
  ...index.matchAll(
    /^\| (A\d{3}) \|.*\[(A\d{3}-[a-z0-9-]+)\]\(((?:\.\.\/)+[a-z0-9-]+\/tests\/attacks\/)?\2\.test\.ts\)/gmu,
  ),
].map(([, id = '', file = '', prefix = '']) => ({ id, file: `${prefix}${file}.test.ts` }));

const idOf = (path: string) => FILE.exec(path.split('/').pop() ?? '')?.[1] ?? '';

describe('attack suite index', () => {
  it('lists every attack file once, and every listed file exists', () => {
    expect(rows.map((r) => r.file).sort()).toEqual([...files.keys()].sort());
    expect(new Set(rows.map((r) => r.id)).size).toBe(rows.length);
  });

  it('numbers the attacks from A001 with no gaps, across every package', () => {
    const ids = [...files.keys()].map(idOf).sort();

    expect(ids).toEqual(ids.map((_, i) => `A${String(i + 1).padStart(3, '0')}`));
  });

  it('gives each file a header that names its number, its attack and what stops it', () => {
    const missing = [...files].filter(([path, url]) => {
      const text = readFileSync(url, 'utf8');

      return !text.startsWith(`// ${idOf(path)}: `) || !text.includes('// Stopped by: ');
    });

    expect(missing).toEqual([]);
  });
});
