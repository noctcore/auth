import { describe, expect, it } from 'vitest';

import { normalizeEmail } from '../../src/shared/email';

describe('normalizeEmail', () => {
  it('trims and lowercases so one address has one spelling', () => {
    expect(normalizeEmail('  Alice@Example.COM ')).toBe('alice@example.com');
  });

  it('applies NFC so composed and decomposed forms are the same account', () => {
    expect(normalizeEmail('josé@example.com')).toBe(normalizeEmail('josé@example.com'));
  });

  it.each([
    '',
    'no-at',
    '@example.com',
    'a@b',
    'a@b.',
    'a@@b.com',
    'a b@c.com',
    'a\u0000@b.com',
    `${'a'.repeat(65)}@b.com`,
    7,
  ])('refuses %j', (value) => {
    expect(normalizeEmail(value)).toBeNull();
  });
});
