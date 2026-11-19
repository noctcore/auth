// Proves the exact-lookup lint rule (scripts/eslint/exact-email-lookup.js)
// refuses every spelling of a reach for `findCredentialByEmail` outside the
// core it promises to, and leaves the core's own method alone.
import { Linter } from 'eslint';
import tseslint from 'typescript-eslint';
import { describe, expect, it } from 'vitest';

import { exactEmailLookup } from '../../../../scripts/eslint/exact-email-lookup.js';

const linter = new Linter();

const config: Linter.Config[] = [
  {
    files: ['**/*.ts'],
    languageOptions: { parser: tseslint.parser, ecmaVersion: 2022, sourceType: 'module' },
    rules: { 'no-restricted-syntax': ['error', ...exactEmailLookup] },
  },
];

function errors(code: string): string[] {
  return linter.verify(code, config, 'flow.ts').map((m) => m.message);
}

describe('the exact-lookup lint rule', () => {
  it.each([
    ['the core method', 'await core.findCredentialByEmail(email);'],
    ['the core method behind a receiver', 'await this.core.findCredentialByEmail(email);'],
    ['the core method by a string key', "await core['findCredentialByEmail'](email);"],
    ['another method on the store', 'await users.findById(id);'],
    ['an unrelated destructured key', 'const { findById } = users;'],
  ])('allows %s', (_, code) => {
    expect(errors(code)).toEqual([]);
  });

  it.each([
    ['a member on the store', 'await users.findCredentialByEmail(email);'],
    ['a member on a nested store', 'await deps.users.findCredentialByEmail(email);'],
    ['an optional member', 'await users?.findCredentialByEmail(email);'],
    ['a computed string key', "await users['findCredentialByEmail'](email);"],
    ['a computed template key', 'await users[`findCredentialByEmail`](email);'],
    ['a destructured key', 'const { findCredentialByEmail } = users;'],
    ['a destructured key, renamed', 'const { findCredentialByEmail: find } = users;'],
    ['a destructured string key', "const { 'findCredentialByEmail': find } = users;"],
    ['a destructured computed key', "const { ['findCredentialByEmail']: find } = users;"],
    ['a destructured template key', 'const { [`findCredentialByEmail`]: find } = users;'],
    [
      'a destructured key in a parameter',
      'const f = ({ findCredentialByEmail }) => findCredentialByEmail;',
    ],
    ['a method detached from core', 'const { findCredentialByEmail } = core;'],
  ])('refuses %s', (_, code) => {
    expect(errors(code)).toEqual([
      'Look users up by address with core.findCredentialByEmail (exact match only).',
    ]);
  });
});
