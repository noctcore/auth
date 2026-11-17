// Proves the secret-comparison lint rule (scripts/eslint/no-secret-comparison.js)
// catches every spelling of a secret it promises to, and leaves shape and
// presence checks alone.
import { RuleTester } from 'eslint';
import tseslint from 'typescript-eslint';
import { describe, it } from 'vitest';

import rule from '../../../../scripts/eslint/no-secret-comparison.js';

RuleTester.describe = describe;
RuleTester.it = it;

const tester = new RuleTester({
  languageOptions: { parser: tseslint.parser, ecmaVersion: 2022, sourceType: 'module' },
});

const caught = (code: string) => ({ code, errors: [{ messageId: 'secret' }] });

tester.run('no-secret-comparison', rule, {
  valid: [
    'if (tokenHash === undefined) {}',
    "if (row.tokenHash === '') {}",
    "if (typeof token === 'string') {}",
    "if (result.code === 'invalid_credentials') {}",
    'if (row?.tokenHash !== null) {}',
    'if (count === limit) {}',
    'hexDigestsEqual(row.tokenHash, expected);',
    'a.equals(b);',
    "name.localeCompare('x');",
  ],
  invalid: [
    caught('row?.tokenHash === x;'),
    caught("rec['passwordHash'] === x;"),
    caught('(tokenHash as string) === x;'),
    caught('tokenHash! === x;'),
    caught('x !== stored.secret;'),
    caught('given == expectedDigest;'),
    caught('mac === other;'),
    caught('input.code === found.code;'),
    caught('sig === expected;'),
    caught('header.signature !== computed;'),
    caught('(tokenHash satisfies string) === x;'),
    caught('Buffer.compare(a, b);'),
    caught('crypto.timingSafeEqual(a, b);'),
    caught('timingSafeEqual(a, b);'),
    caught('tokenHash.equals(x);'),
    caught('x.equals(row.tokenHash);'),
    caught('Object.is(tokenHash, x);'),
    caught("rec['secret'].localeCompare(x);"),
  ],
});
