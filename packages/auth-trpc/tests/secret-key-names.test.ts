import { describe, expect, it } from 'vitest';
import { isSecretKey } from '../src/secret-queries';

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
  ])('does not flag %s', (key) => {
    expect(isSecretKey(key)).toBe(false);
  });
});
