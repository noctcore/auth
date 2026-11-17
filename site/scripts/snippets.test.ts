import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'bun:test';

const SITE = join(dirname(fileURLToPath(import.meta.url)), '..');

/** The AuthToken model block, without comments and blank lines. */
function authTokenModel(schemaPath: string): string {
  const schema = readFileSync(schemaPath, 'utf8');
  const start = schema.indexOf('model AuthToken {');
  const end = schema.indexOf('\n}', start);

  expect(start).toBeGreaterThan(-1);

  return schema
    .slice(start, end + 2)
    .split('\n')
    .map((line) => line.replace(/\/\/.*$/u, '').trim())
    .filter((line) => line !== '')
    .join('\n');
}

describe('code sample schema', () => {
  it('copies the AuthToken model of @noctcore/auth-prisma exactly', () => {
    expect(authTokenModel(join(SITE, 'snippets/prisma/schema.prisma'))).toBe(
      authTokenModel(join(SITE, '../packages/auth-prisma/prisma/auth.prisma')),
    );
  });
});
