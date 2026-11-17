import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'bun:test';

const SITE = join(dirname(fileURLToPath(import.meta.url)), '..');

/** One model block, without comments and blank lines. */
function model(schemaPath: string, name: string): string {
  const schema = readFileSync(schemaPath, 'utf8');
  const start = schema.indexOf(`model ${name} {`);
  const end = schema.indexOf('\n}', start);

  expect(start).toBeGreaterThan(-1);

  return schema
    .slice(start, end + 2)
    .split('\n')
    .map((line) => line.replace(/\/\/.*$/u, '').trim())
    .filter((line) => line !== '')
    .join('\n');
}

const MODELS = [
  'AuthToken',
  'AuthTwoFactor',
  'AuthRecoveryCodes',
  'AuthTrustedDevice',
  'AuthStepUp',
  'AuthMember',
  'AuthMemberScope',
];

describe('code sample schema', () => {
  for (const name of MODELS) {
    it(`copies the ${name} model of @noctcore/auth-prisma exactly`, () => {
      expect(model(join(SITE, 'snippets/prisma/schema.prisma'), name)).toBe(
        model(join(SITE, '../packages/auth-prisma/prisma/auth.prisma'), name),
      );
    });
  }
});
