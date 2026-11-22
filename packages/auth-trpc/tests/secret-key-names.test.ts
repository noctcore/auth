import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { isSecretKey, words } from '../src/secret-queries';

describe('isSecretKey', () => {
  it.each([
    // the secret word alone, any case
    'password',
    'currentPassword',
    'reset_token',
    'OTP-code',
    'pin',
    'secret',
    'totp',
    // plurals
    'passwords',
    'tokens',
    'secrets',
    'recoveryCodes',
    'backupCodes',
    'apiTokens',
    'accessTokens',
    'pins',
    // run together in one lower-case word
    'resettoken',
    'resetToken',
    'otpcode',
    'verificationcode',
    'accesstokens',
    'refreshtoken',
    'csrftoken',
    'newpassword',
    'authcode',
    // api key, in each spelling
    'apiKey',
    'apikey',
    'api_key',
    'api-keys',
    'apiKeys',
    'apikeys',
    // run together behind a lead the camelCase form already flags
    'pincode',
    'pinCode',
    'newpin',
    'oldpin',
    'currentpin',
    'twofactorcode',
    '2facode',
    'hotpcode',
    'hotp',
    'newotp',
    // short password spelling
    'pwd',
    'newPwd',
    'currentpwd',
    // a secret as the last word
    'jwt',
    'accessJwt',
    'refreshjwt',
    'credential',
    'credentials',
    'userCredentials',
    'bearer',
    'authorization',
    // key pairs, two words or one
    'privateKey',
    'private_key',
    'privatekey',
    'privateKeys',
    'accessKey',
    'accessKeyId',
    'secretAccessKey',
    'signingKey',
    'encryptionKey',
  ])('flags %s', (key) => {
    expect(isSecretKey(key)).toBe(true);
  });

  it.each([
    'postcode',
    'zipcode',
    'barcode',
    'qrcode',
    'unicode',
    'opcode',
    'pinned',
    'spin',
    'spinner',
    'tokenizer',
    'secretary',
    'key',
    'sortKey',
    'api',
    'email',
    'name',
    'limit',
    'cursor',
    'description',
    'accessLevel',
    'hotpot',
    '',
    // the new words, as part of a name that is not a secret
    'publicKey',
    'keyboard',
    'monkey',
    'accessLevel',
    'jwtIssuer',
    'jwtAudience',
    'credentialId',
    'credentialType',
    'authorizationUrl',
    'authorizationStatus',
    'newsletter',
    'newspin',
    'currentPage',
    'oldValue',
    'twofactorEnabled',
    'is2faEnabled',
    'hotpotato',
    'cwd',
    // ambiguous, deliberately out (see the changeset)
    'sessionId',
    'pass',
    'passCount',
    'signature',
  ])('does not flag %s', (key) => {
    expect(isSecretKey(key)).toBe(false);
  });
});

// The splitter the linear one replaced: correct, but its second step
// backtracks over every run of capitals, quadratic on a long all-caps key.
function regexWords(key: string): string[] {
  return key
    .replace(/([a-z0-9])([A-Z])/gu, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/gu, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/u)
    .filter((word) => word !== '');
}

const RUNS = { seed: 20_261_122, numRuns: 2_000 };

describe('words', () => {
  it.each([
    ['currentPassword', ['current', 'password']],
    ['reset_token', ['reset', 'token']],
    ['OTP-code', ['otp', 'code']],
    ['OTPCode', ['otp', 'code']],
    ['getHTTPResponse', ['get', 'http', 'response']],
    ['ABC', ['abc']],
    ['a1B', ['a1', 'b']],
    ['', []],
  ])('splits %s', (key, expected) => {
    expect(words(key)).toEqual(expected);
  });

  it('gives the same words as the regex splitter on key-like names', () => {
    const char = fc.constantFrom(...'aAbBcCxXyYzZ019_- .'.split(''));

    fc.assert(
      fc.property(fc.string({ unit: char, maxLength: 40 }), (key) => {
        expect(words(key)).toEqual(regexWords(key));
      }),
      RUNS,
    );
  });

  it('gives the same words as the regex splitter on any string', () => {
    fc.assert(
      fc.property(fc.string({ unit: 'grapheme', maxLength: 40 }), (key) => {
        expect(words(key)).toEqual(regexWords(key));
      }),
      RUNS,
    );
  });

  // 100k characters: the regex splitter took about 0.6 s on 32k capitals and
  // grows with the square of the length (about 6 s here). The linear split
  // takes a few milliseconds; the bound is loose so a slow CI box stays green.
  it.each([
    ['all capitals', 'A'.repeat(100_000)],
    ['run-together lower case', 'a'.repeat(100_000)],
    ['alternating case', 'aB'.repeat(50_000)],
    ['capital runs before lower case', 'ABCd'.repeat(25_000)],
  ])('splits a 100k character key of %s in linear time', (_name, key) => {
    const started = performance.now();

    isSecretKey(key);

    expect(performance.now() - started).toBeLessThan(500);
  });
});
