/**
 * Post-build check of dist/. A wrong `base` builds green and 404s every asset,
 * so this reads the emitted HTML: the overview exists and every root-relative
 * href/src sits under /auth/ and resolves to an emitted file.
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const BASE = '/auth';
const DIST = join(resolve(dirname(fileURLToPath(import.meta.url)), '..'), 'dist');

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? walk(path) : [path];
  });
}

function emitted(pathname: string): boolean {
  const rel = decodeURIComponent(pathname.slice(BASE.length + 1));
  const candidates = rel === '' || rel.endsWith('/') ? [join(DIST, rel, 'index.html')] : [join(DIST, rel), join(DIST, rel, 'index.html')];
  return candidates.some((c) => existsSync(c));
}

const failures: string[] = [];
if (!existsSync(join(DIST, 'index.html'))) {
  console.error('check-build: dist/index.html was not emitted');
  process.exit(1);
}

const pages = walk(DIST).filter((f) => f.endsWith('.html'));
const refPattern = /\s(?:href|src)="(\/[^"#?]*)[^"]*"/g;
let checked = 0;
for (const page of pages) {
  for (const match of readFileSync(page, 'utf8').matchAll(refPattern)) {
    const target = match[1] ?? '';
    if (target.startsWith('//')) continue;
    checked++;
    if (!target.startsWith(`${BASE}/`)) failures.push(`${page.slice(DIST.length)}: "${target}" is outside the ${BASE}/ base`);
    else if (!emitted(target)) failures.push(`${page.slice(DIST.length)}: "${target}" does not resolve to an emitted file`);
  }
}

console.log(`check-build: ${pages.length} HTML pages, ${checked} root-relative references checked`);
if (failures.length > 0) {
  console.error(`check-build: ${failures.length} failure(s)\n  ${[...new Set(failures)].slice(0, 50).join('\n  ')}`);
  process.exit(1);
}
