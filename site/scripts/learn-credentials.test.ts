// Keeps the numbers on five Learn pages (passwords, why tokens are hashed,
// entropy and tokens, password reset, email verification), their code samples
// and their diagrams tied to the package source, the way learn-numbers.test.ts
// does for the pilot pages. Two of the five (entropy and tokens, why tokens
// are hashed) already have their page facts checked there; this file adds the
// other three pages, the samples and the diagram constants.
//
// A page listed in PAGES may hold no number that is not a fact below, a
// value the auth guide gives (GUIDE, quoted as the guide's, not the
// package's), an attack id, an algorithm name or an ordered list marker.
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  DEFAULT_DOOR_LIMITS,
  DEFAULT_PASSWORD_POLICY,
  generateToken,
  TOKEN_BYTES,
} from '@noctcore/auth';
import { describe, expect, it } from 'bun:test';
import { emailVerification } from '../snippets/learn/email-verification';
import { passwordReset } from '../snippets/learn/password-reset';
import { hashing, policy } from '../snippets/learn/passwords';
import {
  attackLinkTests,
  DIAGRAMS,
  diagram,
  HOUR,
  inUnit,
  LEARN,
  MINUTE,
  ms,
  only,
  page,
  read,
  source,
  strayLines,
  missingFacts,
} from './learn-checks';

/** A named constant in a diagram component. */
const diagramConst = (name: string, constant: string) =>
  Number(only(diagram(name), new RegExp(`const ${constant} = (\\d+);`, 'u')));

// Values from the code ------------------------------------------------------

const ARGON2 = 'auth/src/password/argon2.ts';
const argon2Default = /export const DEFAULT_ARGON2ID = \{ memoryCost: ([\d_]+), timeCost: (\d+), parallelism: (\d+) \}/u.exec(
  source(ARGON2),
);
const owaspPasses = Number(
  /export const OWASP_ARGON2ID = \{ memoryCost: [\d_]+, timeCost: (\d+), parallelism: \d+ \}/u.exec(
    source(ARGON2),
  )?.[1],
);
/** The guide's floor as the hasher's own comment states it. */
const guideFloor = /the auth guide's \((\d+) MiB with (\d+) passes\)/u.exec(source(ARGON2));
const memoryMiB = hashing.memoryCost / 1024;
const minLengthFloor = Number(
  read('auth/src/create-auth.ts', /if \(policy\.minLength < (\d+)\)/u),
);
const prefixChars = Number(read('auth/src/password/breach.ts', /const prefix = digest\.slice\(0, (\d+)\);/u));

const SETTINGS = 'auth/src/flows/resolve-settings.ts';
const resetTtl = /config\.passwordReset\?\.ttl,\s*resetKind === 'code' \? '(\w+)' : '(\w+)'/u.exec(
  source(SETTINGS),
);
const verificationTtl = /config\.emailVerification\?\.ttl,\s*verificationKind === 'code' \? '(\w+)' : '(\w+)'/u.exec(
  source(SETTINGS),
);
const ticketTtl = read(SETTINGS, /ticketTtl,\s*'(\w+)'/u);

const resetMail = DEFAULT_DOOR_LIMITS['password-reset-mail'];
const resetDoor = DEFAULT_DOOR_LIMITS['password-reset'];
const resetAddress = DEFAULT_DOOR_LIMITS['password-reset-code-address'];
const verificationMail = DEFAULT_DOOR_LIMITS['email-verification-request'];
const addressMinutes = inUnit(resetAddress.window, MINUTE);

const WORDS = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine'];

// The facts -----------------------------------------------------------------

const PAGES: Record<string, readonly string[]> = {
  passwords: [
    `${memoryMiB} MiB of memory, ${hashing.timeCost} passes and ${hashing.parallelism} lane`,
    `must be ${policy.minLength} to ${policy.maxLength} characters`,
    `The package uses ${policy.minLength}`,
    `refuses a configured minimum below ${minLengthFloor}`,
    `The package allows ${policy.maxLength}`,
    `OWASP's floor is ${owaspPasses} passes at ${memoryMiB} MiB`,
    `the guide's is ${guideFloor?.[2]} passes at ${guideFloor?.[1]} MiB`,
  ],
  'password-reset': [
    `the per-account mail limit (${resetMail.limit} an hour)`,
    `(${resetDoor.limit} a ${resetDoor.window === '1m' ? 'minute' : resetDoor.window} per IP by default)`,
    `A reset link is ${TOKEN_BYTES} random bytes`,
    `the mail carries ${passwordReset.digits} digits instead`,
    `a ticket valid for ${inUnit(passwordReset.ticketTtl, MINUTE)} minutes`,
    `${passwordReset.maxAttempts} wrong guesses | At the code that was mailed`,
    `${resetAddress.limit} guesses per ${addressMinutes} minutes per address`,
    `spend those ${resetAddress.limit} guesses`,
    `for ${addressMinutes} minutes. That is`,
    `accept the ${addressMinutes}-minute nuisance`,
  ],
  'email-verification': [
    `mails an ${emailVerification.digits}-digit code`,
    `A code lives ${inUnit(emailVerification.ttl, MINUTE)} minutes`,
    `allows ${emailVerification.maxAttempts} wrong guesses`,
    `limited to ${verificationMail.limit} mails an hour per account`,
    `(${TOKEN_BYTES} random bytes, stored as SHA-256, ${inUnit(verificationTtl?.[2] ?? '', HOUR)} hours)`,
    `capped at ${emailVerification.maxAttempts} attempts`,
  ],
};

/** Every page of this file, the two whose numbers learn-numbers.test.ts checks included. */
const PAGE_SLUGS = [
  'passwords',
  'why-tokens-are-hashed',
  'entropy-and-tokens',
  'password-reset',
  'email-verification',
];

/** What the auth guide recommends, quoted on the pages as the guide's own numbers. */
const GUIDE: Record<string, readonly string[]> = {
  passwords: ['The guide suggests 8 or 10', 'The guide suggests 50 to 100'],
  'password-reset': [],
  'email-verification': ['suggests 8 digits'],
};

/** Words that stand for a number the code holds. */
const WORDED: Record<string, readonly string[]> = {
  passwords: [`the first ${WORDS[prefixChars]} characters`, `the ${WORDS[prefixChars]}-character prefix`],
  'password-reset': ['valid for an hour'],
  'email-verification': [],
};

describe('Learn credential page numbers', () => {
  for (const [slug, facts] of Object.entries(PAGES)) {
    const text = page(slug);
    const guide = GUIDE[slug] ?? [];

    it(`${slug} states the values the code uses`, () => {
      expect(missingFacts(text, [...facts, ...(WORDED[slug] ?? [])])).toEqual([]);
    });

    it(`${slug} quotes the guide where it says it does`, () => {
      expect(missingFacts(text, guide)).toEqual([]);
    });

    it(`${slug} holds no number that is not checked here`, () => {
      expect(strayLines(text, [...facts, ...guide])).toEqual([]);
    });
  }

  it('reads the facts it builds on', () => {
    expect(guideFloor).not.toBeNull();
    expect(resetTtl).not.toBeNull();
    expect(verificationTtl).not.toBeNull();
    expect(WORDS[prefixChars]).toBeDefined();
    expect(ms(resetMail.window)).toBe(HOUR);
    expect(ms(verificationMail.window)).toBe(HOUR);
  });
});

describe('Learn credential code samples and diagrams', () => {
  it('writes out the Argon2id defaults the hasher uses', () => {
    expect(argon2Default).not.toBeNull();
    expect([
      Number(argon2Default?.[1]?.replaceAll('_', '')),
      Number(argon2Default?.[2]),
      Number(argon2Default?.[3]),
    ]).toEqual([hashing.memoryCost, hashing.timeCost, hashing.parallelism]);
    expect(Number.isInteger(memoryMiB)).toBe(true);
  });

  it('writes out the default password policy', () => {
    expect(policy).toEqual(DEFAULT_PASSWORD_POLICY);
  });

  it('draws the breach check prefix the code sends', () => {
    expect(diagramConst('PasswordStorage', 'PREFIX_CHARS')).toBe(prefixChars);
  });

  it('draws the token size the package mints', () => {
    expect(diagramConst('TokenEntropy', 'TOKEN_BYTES')).toBe(TOKEN_BYTES);
    expect(generateToken()).toHaveLength(TOKEN_BYTES * 2);
  });

  it('writes out the password reset defaults resolve-settings.ts uses', () => {
    expect<string>(passwordReset.kind).toBe(read(SETTINGS, /config\.passwordReset\?\.kind \?\? '(\w+)'/u));
    expect(ms(passwordReset.ttl)).toBe(ms(resetTtl?.[2] ?? ''));
    expect(ms(passwordReset.ttl)).toBe(HOUR);
    expect(passwordReset.digits).toBe(Number(read(SETTINGS, /passwordReset\?\.digits \?\? (\d+)/u)));
    expect(passwordReset.maxAttempts).toBe(
      Number(read(SETTINGS, /passwordReset\?\.maxAttempts \?\? (\d+)/u)),
    );
    expect(ms(passwordReset.ticketTtl)).toBe(ms(ticketTtl));
    expect(String(passwordReset.markEmailVerified)).toBe(
      read(SETTINGS, /passwordReset\?\.markEmailVerified \?\? (\w+)/u),
    );
  });

  it('writes out the email verification defaults resolve-settings.ts uses', () => {
    expect<string>(emailVerification.kind).toBe(
      read(SETTINGS, /config\.emailVerification\?\.kind \?\? '(\w+)'/u),
    );
    expect(ms(emailVerification.ttl)).toBe(ms(verificationTtl?.[1] ?? ''));
    expect(emailVerification.digits).toBe(
      Number(read(SETTINGS, /emailVerification\?\.digits \?\? (\d+)/u)),
    );
    expect(emailVerification.maxAttempts).toBe(
      Number(read(SETTINGS, /emailVerification\?\.maxAttempts \?\? (\d+)/u)),
    );
    expect(String(emailVerification.linkWithoutSession)).toBe(
      read(SETTINGS, /emailVerification\?\.linkWithoutSession \?\? (\w+);/u),
    );
  });
});

describe('Learn credential attack links', () => {
  attackLinkTests(PAGE_SLUGS);
});

describe('Learn credential files', () => {
  const FILES = [
    ...PAGE_SLUGS.map(
      (slug) => (existsSync(join(LEARN, `${slug}.mdx`)) ? join(LEARN, `${slug}.mdx`) : join(LEARN, `${slug}.md`)),
    ),
    ...[
      'PasswordStorage',
      'PasswordRehash',
      'TokenHashing',
      'TokenEntropy',
      'PasswordResetLink',
      'EmailVerificationSquatter',
    ].map((name) => join(DIAGRAMS, `${name}.astro`)),
  ];

  it('use no em or en dashes', () => {
    for (const file of FILES) expect([file, /[–—]/u.test(readFileSync(file, 'utf8'))]).toEqual([file, false]);
  });
});
