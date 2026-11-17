// Keeps the attack suite and its index (ATTACKS.md) in step: every numbered
// file has a row and a header naming its attack, every row has a file, and
// the numbers run from A001 with no gaps, so a deleted attack test shows up as
// a hole instead of disappearing quietly.
import { readdirSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const DIR = new URL('./', import.meta.url);
const FILE = /^(A\d{3})-[a-z0-9-]+\.test\.ts$/u;

const files = readdirSync(DIR).filter((name) => FILE.test(name));
const index = readFileSync(new URL('ATTACKS.md', DIR), 'utf8');

const rows = [...index.matchAll(/^\| (A\d{3}) \|.*\[(A\d{3}-[a-z0-9-]+)\]\(\2\.test\.ts\)/gmu)].map(
  ([, id = '', file = '']) => ({ id, file: `${file}.test.ts` }),
);

describe('attack suite index', () => {
  it('lists every attack file once, and every listed file exists', () => {
    expect(rows.map((r) => r.file).sort()).toEqual([...files].sort());
    expect(new Set(rows.map((r) => r.id)).size).toBe(rows.length);
  });

  it('numbers the attacks from A001 with no gaps', () => {
    const ids = files.map((name) => FILE.exec(name)?.[1] ?? '').sort();

    expect(ids).toEqual(ids.map((_, i) => `A${String(i + 1).padStart(3, '0')}`));
  });

  it('gives each file a header that names its number, its attack and what stops it', () => {
    const missing = files.filter((name) => {
      const text = readFileSync(new URL(name, DIR), 'utf8');
      const id = FILE.exec(name)?.[1] ?? '';

      return !text.startsWith(`// ${id}: `) || !text.includes('// Stopped by: ');
    });

    expect(missing).toEqual([]);
  });
});
