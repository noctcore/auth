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
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DEFAULT_DOOR_LIMITS,
  DEFAULT_PASSWORD_POLICY,
  generateToken,
  TOKEN_BYTES,
  toMilliseconds,
  type Duration,
} from '@noctcore/auth';
import { describe, expect, it } from 'bun:test';
import { emailVerification } from '../snippets/learn/email-verification';
import { passwordReset } from '../snippets/learn/password-reset';
import { hashing, policy } from '../snippets/learn/passwords';

const SITE = join(dirname(fileURLToPath(import.meta.url)), '..');
const REPO = join(SITE, '..');
const LEARN = join(SITE, 'src/content/docs/learn');
const DIAGRAMS = join(SITE, 'src/components/docs/diagrams');

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

function page(slug: string): string {
  const md = join(LEARN, `${slug}.md`);

  return readFileSync(existsSync(md) ? md : join(LEARN, `${slug}.mdx`), 'utf8');
}

function source(path: string): string {
  return readFileSync(join(REPO, 'packages', path), 'utf8');
}

/** The first capture of `pattern`, which must match exactly once. */
function read(path: string, pattern: RegExp): string {
  const matches = [...source(path).matchAll(new RegExp(pattern.source, `${pattern.flags}g`))];

  expect(matches.map((m) => m[0])).toHaveLength(1);

  return matches[0]?.[1] ?? '';
}

/** A named constant in a diagram component. */
function diagramConst(file: string, name: string): number {
  const text = readFileSync(join(DIAGRAMS, file), 'utf8');
  const value = new RegExp(`const ${name} = (\\d+);`, 'u').exec(text)?.[1];

  expect(value).toBeDefined();

  return Number(value);
}

function inUnit(duration: string | Duration, unit: number): number {
  const ms = toMilliseconds(duration as Duration);

  expect(ms % unit).toBe(0);

  return ms / unit;
}

const ms = (value: string | Duration) => toMilliseconds(value as Duration);

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
const resetTtl = /config\.passwordReset\?\.ttl \?\? \(resetKind === 'code' \? '(\w+)' : '(\w+)'\)/u.exec(
  source(SETTINGS),
);
const verificationTtl = /config\.emailVerification\?\.ttl \?\? \(verificationKind === 'code' \? '(\w+)' : '(\w+)'\)/u.exec(
  source(SETTINGS),
);
const ticketTtl = read(SETTINGS, /ticketTtl \?\? '(\w+)'/u);

const resetMail = DEFAULT_DOOR_LIMITS['password-reset-mail'];
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

const NOT_NUMBERS = [
  /\]\([^)]*\)/gu, // link targets
  /\bA\d{3}\b/gu, // attack ids
  /\bHMAC-SHA-256\b|\bSHA-256\b|\bSHA-1\b/gu,
  /\bargon2(?:id)?\b/giu, // the algorithm, its module and its factory
  /^\d+\. /gmu, // ordered list markers
];

function missingFacts(text: string, facts: readonly string[]): string[] {
  return facts.filter((fact) => !text.includes(fact));
}

function strayLines(text: string, facts: readonly string[]): string[] {
  let rest = text;

  for (const fact of [...facts].sort((a, b) => b.length - a.length)) rest = rest.replace(fact, ' ');
  for (const pattern of NOT_NUMBERS) rest = rest.replace(pattern, ' ');

  return rest.split('\n').filter((line) => /\d/u.test(line));
}

describe('Learn batch A page numbers', () => {
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

describe('Learn batch A code samples and diagrams', () => {
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
    expect(diagramConst('PasswordStorage.astro', 'PREFIX_CHARS')).toBe(prefixChars);
  });

  it('draws the token size the package mints', () => {
    expect(diagramConst('TokenEntropy.astro', 'TOKEN_BYTES')).toBe(TOKEN_BYTES);
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

describe('Learn batch A attack links', () => {
  const index = readFileSync(join(REPO, 'packages/auth/tests/attacks/ATTACKS.md'), 'utf8');
  const LINK =
    /\[(A\d{3})[^\]]*\]\(https:\/\/github\.com\/noctcore\/auth\/blob\/main\/(packages\/[a-z-]+\/tests\/attacks\/(A\d{3})-[a-z0-9-]+\.test\.ts)\)/gu;
  /** Names ATTACKS.md uses for a page besides its title. */
  const ALIASES: Record<string, readonly string[]> = {
    'email-verification': ['Email verification'],
  };
  const SLUGS = [
    'passwords',
    'why-tokens-are-hashed',
    'entropy-and-tokens',
    'password-reset',
    'email-verification',
  ];

  for (const slug of SLUGS) {
    const text = page(slug);
    const title = /^title: (.+)$/mu.exec(text)?.[1] ?? '';
    const names = new Set([title, ...(ALIASES[slug] ?? [])]);
    const links = [...text.matchAll(LINK)];

    it(`${slug} links attack tests that exist`, () => {
      expect(links.length).toBeGreaterThan(0);

      for (const [, label, path, id] of links) {
        expect(label).toBe(id);
        expect(existsSync(join(REPO, path ?? ''))).toBe(true);
      }
    });

    it(`${slug} links every attack ATTACKS.md files under it, in its table`, () => {
      const named = [...index.matchAll(/^\| (A\d{3}) \| [^|]+ \| ([^|]+) \|/gmu)]
        .filter(([, , pages = '']) => pages.split(';').some((p) => names.has(p.trim())))
        .map(([, id]) => id);
      const table = text.slice(text.indexOf('<div class="nc-attacks">'));
      const tabled = new Set([...table.matchAll(LINK)].map(([, id]) => id));

      expect(named.length).toBeGreaterThan(0);
      expect(named.filter((id) => !tabled.has(id))).toEqual([]);
    });
  }
});

describe('Learn batch A files', () => {
  const FILES = [
    ...['passwords', 'why-tokens-are-hashed', 'entropy-and-tokens', 'password-reset', 'email-verification'].map(
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
