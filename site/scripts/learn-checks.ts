// What the Learn page tests share: where the pages, diagrams, samples and
// package source live, readers that fail loudly when a value is renamed or
// duplicated, the "no number the tests do not know" check, and the attack
// link checks every page gets. Not a test file: bun only runs *.test.ts.
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { toMilliseconds, type Duration } from '@noctcore/auth';
import { expect, it } from 'bun:test';

export const SITE = join(dirname(fileURLToPath(import.meta.url)), '..');
export const REPO = join(SITE, '..');
export const LEARN = join(SITE, 'src/content/docs/learn');
export const DIAGRAMS = join(SITE, 'src/components/docs/diagrams');

export const MINUTE = 60_000;
export const HOUR = 60 * MINUTE;
export const DAY = 24 * HOUR;

// Readers --------------------------------------------------------------------

/** A page's Markdown or MDX, frontmatter included. */
export function page(slug: string): string {
  const md = join(LEARN, `${slug}.md`);

  return readFileSync(existsSync(md) ? md : join(LEARN, `${slug}.mdx`), 'utf8');
}

/** A diagram component's source. */
export const diagram = (name: string) => readFileSync(join(DIAGRAMS, `${name}.astro`), 'utf8');

/** A code sample's source, by file name without the extension. */
export const snippet = (name: string) =>
  readFileSync(join(SITE, 'snippets/learn', `${name}.ts`), 'utf8');

/** The source of a package file, relative to `packages/`. */
export const source = (path: string) => readFileSync(join(REPO, 'packages', path), 'utf8');

/**
 * The first capture of `pattern` in `text`. The pattern has to match exactly
 * once, so a renamed or duplicated constant fails loudly instead of reading
 * the wrong value.
 */
export function only(text: string, pattern: RegExp): string {
  const matches = [...text.matchAll(new RegExp(pattern.source, `${pattern.flags}g`))];

  expect(matches.map((m) => m[0])).toHaveLength(1);

  return matches[0]?.[1] ?? '';
}

/** `only`, in a package file. */
export const read = (path: string, pattern: RegExp) => only(source(path), pattern);

export const num = (path: string, pattern: RegExp) => Number(read(path, pattern));

/** Every capture of `pattern` in a package file, which must agree on one value. */
export function readAll(path: string, pattern: RegExp, count: number): string {
  const values = [...source(path).matchAll(new RegExp(pattern.source, `${pattern.flags}g`))].map(
    (m) => m[1] ?? '',
  );

  expect(values).toHaveLength(count);
  expect(new Set(values).size).toBe(1);

  return values[0] ?? '';
}

// Durations ------------------------------------------------------------------

export const ms = (duration: string | Duration) => toMilliseconds(duration as Duration);

/** A duration in the unit the pages write it in; it has to be a whole number of them. */
export function inUnit(duration: string | Duration, unit: number): number {
  expect(ms(duration) % unit).toBe(0);

  return ms(duration) / unit;
}

// Numbers on a page ----------------------------------------------------------

/** What may hold a digit on a checked page without being a fact. */
const NOT_NUMBERS = [
  /\]\([^)]*\)/gu, // link targets
  /\bA\d{3}\b/gu, // attack ids
  /\bHMAC-SHA-256\b|\bSHA-256\b|\bHMAC-SHA-1\b|\bSHA-1\b/gu,
  /\bargon2(?:id)?\b/giu, // the algorithm, its module and its factory (Argon2id)
  /\bRFC \d{4}\b/gu,
  /\bIPv[46]\b/gu, // address family names
  /\bbase64url\b/gu,
  /`@noctcore\/auth` \d+\.\d+/gu, // a past release named in an upgrade note
  /\b(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}\b/gu, // documentation ranges (RFC 5737)
  /^\d+\. /gmu, // ordered list markers
];

/** The facts a page does not state. A fact listed twice must appear twice. */
export function missingFacts(text: string, facts: readonly string[]): string[] {
  return facts.filter((fact, i) => {
    const wanted = facts.slice(0, i + 1).filter((f) => f === fact).length;

    return text.split(fact).length - 1 < wanted;
  });
}

/**
 * The lines that still hold a digit once each listed fact is taken out once
 * (and only once, so a fact phrase repeated in another sentence leaves its
 * number behind) and the allowed non-numbers are removed.
 */
export function strayLines(text: string, facts: readonly string[]): string[] {
  let rest = text;

  // Longest first, so a fact inside a longer one does not leave pieces behind.
  for (const fact of [...facts].sort((a, b) => b.length - a.length)) rest = rest.replace(fact, ' ');
  for (const pattern of NOT_NUMBERS) rest = rest.replace(pattern, ' ');

  return rest.split('\n').filter((line) => /\d/u.test(line));
}

/** The two tests every checked page gets: its facts are there, and no other number is. */
export function numberTests(pages: Record<string, readonly string[]>): void {
  for (const [slug, facts] of Object.entries(pages)) {
    it(`${slug} states the values the code uses`, () => {
      expect(missingFacts(page(slug), facts)).toEqual([]);
    });

    it(`${slug} holds no number that is not checked here`, () => {
      expect(strayLines(page(slug), facts)).toEqual([]);
    });
  }
}

// Attack links ---------------------------------------------------------------

const LINK =
  /\[(A\d{3})[^\]]*\]\(https:\/\/github\.com\/noctcore\/auth\/blob\/main\/(packages\/[a-z-]+\/tests\/attacks\/(A\d{3})-[a-z0-9-]+\.test\.ts)\)/gu;

/** The attack index: one row per attack, with the Learn pages it backs. */
const attackIndex = () =>
  readFileSync(join(REPO, 'packages/auth/tests/attacks/ATTACKS.md'), 'utf8');

/** The links in a page's attack table (`<div class="nc-attacks">`). */
function attackTable(text: string): RegExpExecArray[] {
  const start = text.indexOf('<div class="nc-attacks">');

  expect(start).toBeGreaterThanOrEqual(0);

  return [...text.slice(start, text.indexOf('</div>', start)).matchAll(LINK)] as RegExpExecArray[];
}

/** Names ATTACKS.md still uses for a page besides its title. */
const ALIASES: Record<string, readonly string[]> = {
  'email-verification': ['Email verification'],
};

/**
 * For each page: every attack test it links exists, and every attack
 * ATTACKS.md files under the page's title has a row in its attack table.
 */
export function attackLinkTests(slugs: readonly string[]): void {
  for (const slug of slugs) {
    const text = page(slug);
    const title = /^title: (.+)$/mu.exec(text)?.[1] ?? '';
    const names = new Set([title, `Learn: ${title}`, ...(ALIASES[slug] ?? [])]);
    const links = [...text.matchAll(LINK)];

    it(`${slug} links attack tests that exist`, () => {
      expect(links.length).toBeGreaterThan(0);

      for (const [, label, path, id] of links) {
        expect(label).toBe(id);
        expect(existsSync(join(REPO, path ?? ''))).toBe(true);
      }
    });

    it(`${slug} has a table row for every attack ATTACKS.md files under it`, () => {
      const named = [...attackIndex().matchAll(/^\| (A\d{3}) \| [^|]+ \| ([^|]+) \|/gmu)]
        .filter(([, , pages = '']) => pages.split(';').some((p) => names.has(p.trim())))
        .map(([, id]) => id);
      const rows = new Set(attackTable(text).map(([, id]) => id));

      expect(named.length).toBeGreaterThan(0);
      expect(named.filter((id) => !rows.has(id))).toEqual([]);
    });
  }
}
