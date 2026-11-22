// Keeps the numbers on four Learn pages (second factors, email change,
// invitations, design choices) tied to the code, the same way
// learn-numbers.test.ts does for the pages it lists: each fact is a phrase the
// page must contain, built from the value the code uses, and once the facts
// are taken out no other digit may be left on the page. The pages must link
// every attack test ATTACKS.md files under them, and the code samples and
// diagram constants they draw from are checked against the source too.
//
// A few facts are the auth guide's own values, not the package's: they are
// written out as literals below and marked as such.
import { DEFAULT_DOOR_LIMITS, TOKEN_BYTES } from '@noctcore/auth';
import { describe, expect, it } from 'bun:test';
import { emailChange, freshAuthAge } from '../snippets/learn/email-change';
import { invitationLimits } from '../snippets/learn/invitations';
import { secondFactor } from '../snippets/learn/second-factor';
import {
  attackLinkTests,
  DAY,
  diagram,
  HOUR,
  inUnit,
  MINUTE,
  ms,
  num,
  numberTests,
  only,
  page,
  read,
  readAll,
  source,
  strayLines,
} from './learn-checks';

/** An AttemptRule default in a plugin's options file: `name ?? { limit: 5, window: '15m' }`. */
function ruleDefault(path: string, name: string): { limit: number; window: string } {
  const match = new RegExp(
    `options\\.${name} \\?\\? \\{ limit: (\\d+), window: '(\\w+)' \\}`,
    'u',
  ).exec(source(path));

  expect(match).not.toBeNull();

  return { limit: Number(match?.[1]), window: match?.[2] ?? '' };
}

/** A `const NAME = n * 60_000;` style lifetime, in milliseconds. */
function lifetime(path: string, name: string): number {
  const expr = read(path, new RegExp(`export const ${name} = ([\\d_ *]+);`, 'u'));

  return expr
    .split('*')
    .map((part) => Number(part.trim().replaceAll('_', '')))
    .reduce((a, b) => a * b, 1);
}

// Values from the code ------------------------------------------------------

const TOTP = 'auth/src/plugins/two-factor/totp.ts';
const totpPeriod = num(TOTP, /export const TOTP_PERIOD_SECONDS = (\d+);/u);
const totpDigits = num(TOTP, /export const TOTP_DIGITS = (\d+);/u);
const totpSecretBytes = num(TOTP, /export const TOTP_SECRET_BYTES = (\d+);/u);
const totpDrift = num(TOTP, /export const TOTP_DRIFT_STEPS = (\d+);/u);

const FACTOR_OPTIONS = 'auth/src/plugins/two-factor/options.ts';
const factorAttempts = ruleDefault(FACTOR_OPTIONS, 'attempts');
const factorPerIp = ruleDefault(FACTOR_OPTIONS, 'perIp');
const stepUpWindow = read(FACTOR_OPTIONS, /options\.stepUpWindow,\s*'(\w+)'/u);
const trustedTtl = read(FACTOR_OPTIONS, /option\?\.ttl,\s*'(\w+)'/u);
const trustedMax = num(FACTOR_OPTIONS, /option\?\.maxPerUser \?\? (\d+);/u);
const challengeTtlMs = lifetime(FACTOR_OPTIONS, 'CHALLENGE_TTL_MS');
const challengeCodes = num(FACTOR_OPTIONS, /export const CHALLENGE_MAX_ATTEMPTS = (\d+);/u);
const enrollmentTtlMs = lifetime(FACTOR_OPTIONS, 'ENROLLMENT_TTL_MS');

const RECOVERY = 'auth/src/plugins/two-factor/recovery-codes.ts';
const recoveryCount = num(RECOVERY, /export const RECOVERY_CODE_COUNT = (\d+);/u);
const recoveryLength = num(RECOVERY, /const RECOVERY_CODE_LENGTH = (\d+);/u);
const recoveryAlphabet = read(RECOVERY, /const ALPHABET = '([0-9a-z]+)';/u).length;
const recoveryBits = recoveryLength * Math.log2(recoveryAlphabet);
/** Guesses per hit against a full set: 2^bits codes, `recoveryCount` of them right. */
const guessesExponent = Math.round(recoveryBits - Math.log2(recoveryCount));

const THROTTLE = 'auth/src/throttle/throttle.ts';
const baseLock = read(THROTTLE, /options\.baseLock,\s*'(\w+)'/u);
const maxLock = read(THROTTLE, /options\.maxLock,\s*'(\w+)'/u);
const deviceMaxAge = read(THROTTLE, /options\.deviceMaxAge,\s*'(\w+)'/u);
const lockFactor = num(THROTTLE, /this\.baseLockMs \* (\d+) \*\* Math\.min/u);
const baseLockMinutes = inUnit(baseLock, MINUTE);

const SETTINGS = 'auth/src/flows/resolve-settings.ts';
const changeTtl = read(SETTINGS, /changeKind === 'code' \? '(\w+)'/u);
const changeDigits = num(SETTINGS, /emailChange\?\.digits \?\? (\d+)/u);
const changeAttempts = num(SETTINGS, /emailChange\?\.maxAttempts \?\? (\d+)/u);
const revertTtl = read(SETTINGS, /emailChange\?\.revertTtl,\s*'(\w+)'/u);
const blockAfterRevert = read(SETTINGS, /emailChange\?\.blockAfterRevert,\s*'(\w+)'/u);
const minRevertMs = lifetime(SETTINGS, 'MIN_REVERT_TTL_MS');
const freshAuthDefault = read(SETTINGS, /freshAuthAge,\s*'(\w+)'/u);
const verifyDigits = Number(readAll(SETTINGS, /\.digits \?\? (\d+)/u, 3));
const verifyAttempts = Number(readAll(SETTINGS, /\.maxAttempts \?\? (\d+)/u, 3));
const changeAddressDoor = DEFAULT_DOOR_LIMITS['email-change-address'];

const INVITE_OPTIONS = 'auth/src/plugins/invitations/options.ts';
const inviteTtl = read(INVITE_OPTIONS, /options\.ttl,\s*'(\w+)'/u);
const inviteMaxTtlMs = lifetime(INVITE_OPTIONS, 'MAX_TTL_MS');
const inviteRecheck = read(INVITE_OPTIONS, /options\.recheckInviter \?\? (\w+)/u);
const inviteWithoutSession = read(INVITE_OPTIONS, /options\.acceptWithoutSession \?\? (\w+);/u);
const invitePerInviter = ruleDefault(INVITE_OPTIONS, 'perInviter');
const invitePerAddress = ruleDefault(INVITE_OPTIONS, 'perAddress');
const invitePerIp = ruleDefault(INVITE_OPTIONS, 'perIp');
const legacyRelease = read(
  'auth/src/plugins/invitations/accept.ts',
  /Created before (\d+\.\d+), under the server secret/u,
);

const ARGON2 = 'auth/src/password/argon2.ts';
const argon2 = /export const DEFAULT_ARGON2ID = \{ memoryCost: ([\d_]+), timeCost: (\d+), parallelism: (\d+) \}/u.exec(
  source(ARGON2),
);
const argon2Mib = Number(argon2?.[1]?.replaceAll('_', '')) / 1024;
const policy = /DEFAULT_PASSWORD_POLICY: PasswordPolicy = \{ minLength: (\d+), maxLength: (\d+) \}/u.exec(
  source('auth/src/password/policy.ts'),
);

const SESSION = 'auth/src/session/session-manager.ts';
const touchInterval = read(SESSION, /options\.touchInterval,\s*'(\w+)'/u);
const idleTimeout = /rememberMe \? '(\w+)' : '(\w+)'/u.exec(source(SESSION))?.[2] ?? '';

// The facts -----------------------------------------------------------------

const PAGES: Record<string, readonly string[]> = {
  'second-factors': [
    `RFC 6238 (HMAC-SHA-1, ${totpPeriod}-second steps`,
    `The secret is ${totpSecretBytes * 8} random bits`,
    `${factorAttempts.limit} per ${inUnit(factorAttempts.window, MINUTE)} minutes`,
    `(${baseLockMinutes} minutes, then ${baseLockMinutes * lockFactor}, then ${baseLockMinutes * lockFactor ** 2}, at most an hour)`,
    `${challengeCodes} codes`,
    `within ${enrollmentTtlMs / MINUTE} minutes`,
    `Ten codes of ${recoveryBits} bits each`,
    `about 2^${guessesExponent} guesses per hit`,
    `(${inUnit(stepUpWindow, MINUTE)} minutes by default)`,
    `(${inUnit(trustedTtl, DAY)} days by default)`,
    `the ${challengeTtlMs / MINUTE}-minute lifetime and the ${challengeCodes} codes`,
    `from a ${totpSecretBytes * 8}-bit random secret`,
    // The auth guide's own number.
    'throttling after about 5 failures',
    `the codes are ${recoveryBits} random bits`,
  ],
  'email-change': [
    `\`session.freshAuthAge\`, ${inUnit(freshAuthDefault, MINUTE)} minutes by default`,
    `An ${changeDigits}-digit code`,
    `it lives ${inUnit(changeTtl, MINUTE)} minutes`,
    `allows ${changeAttempts} wrong guesses`,
    `The revert link is ${TOKEN_BYTES} random bytes`,
    `valid for ${inUnit(revertTtl, DAY)} days or more`,
    `lost for ${inUnit(blockAfterRevert, DAY)} days`,
    `expires (${inUnit(revertTtl, DAY)} days by default)`,
    `(${changeAddressDoor.limit} an hour from every account)`,
  ],
  invitations: [
    `${TOKEN_BYTES * 8} bits from the CSPRNG`,
    `${TOKEN_BYTES * 8} random bits leave nothing to search`,
    `created before ${legacyRelease}`,
    `(${inviteMaxTtlMs / DAY} days at most)`,
    `It expires after ${inUnit(inviteTtl, DAY)} days by default, never more than ${inviteMaxTtlMs / DAY}`,
  ],
  'design-choices': [
    // The auth guide's own values.
    '16 MiB, t=3, p=1',
    '8 to 10 minimum, 50 to 100 maximum',
    '8 digits; hashing',
    // The package's.
    `${argon2Mib} MiB, t=${argon2?.[2]}, p=${argon2?.[3]}`,
    `${policy?.[1]} minimum, ${policy?.[2]} maximum`,
    `${policy?.[1]} from the production implementation; ${policy?.[2]} fits passphrases`,
    `${verifyDigits} digits, HMAC at rest, ${verifyAttempts} attempts`,
    `with a ${inUnit(maxLock, HOUR)} h cap`,
    `a device cookie (${inUnit(deviceMaxAge, DAY)} days`,
    `fresh authentication (${inUnit(freshAuthDefault, MINUTE)} min)`,
    `Idle timeouts of ${inUnit(idleTimeout, MINUTE)} minutes`,
  ],
};

describe('Learn account page numbers', () => {
  numberTests(PAGES);

  it('catches a checked number reused in a sentence the facts do not cover', () => {
    const slug = 'second-factors';
    const tampered = `${page(slug)}\nA challenge takes 5 codes and lives 10 minutes.\n`;

    expect(strayLines(tampered, PAGES[slug] ?? [])).toEqual([
      'A challenge takes 5 codes and lives 10 minutes.',
    ]);
  });

  it('says in words only what the code says in numbers', () => {
    // "six digits", "One step of drift", "Ten codes", "ten codes", "a million codes, three of them valid".
    expect(totpDigits).toBe(6);
    expect(totpDrift).toBe(1);
    expect(recoveryCount).toBe(10);
    expect(10 ** totpDigits).toBe(1_000_000);
    expect(2 * totpDrift + 1).toBe(3);
    // "at most an hour", "up to an hour at a time", "stall changes to it for an hour".
    expect(ms(maxLock)).toBe(HOUR);
    expect(ms(changeAddressDoor.window)).toBe(HOUR);
    // "at most once a minute".
    expect(ms(touchInterval)).toBe(MINUTE);
    // "valid for 7 days or more": the default is also the shortest allowed.
    expect(ms(revertTtl)).toBe(minRevertMs);
  });
});

describe('Learn account attack links', () => {
  attackLinkTests(Object.keys(PAGES));
});

describe('Learn account code samples and diagrams', () => {
  it('writes out the two-factor defaults options.ts uses', () => {
    expect([secondFactor.attempts.limit, ms(secondFactor.attempts.window)]).toEqual([
      factorAttempts.limit,
      ms(factorAttempts.window),
    ]);
    expect([secondFactor.perIp.limit, ms(secondFactor.perIp.window)]).toEqual([
      factorPerIp.limit,
      ms(factorPerIp.window),
    ]);
    expect(ms(secondFactor.stepUpWindow)).toBe(ms(stepUpWindow));
    expect(ms(secondFactor.trustedDevices.ttl)).toBe(ms(trustedTtl));
    expect(secondFactor.trustedDevices.maxPerUser).toBe(trustedMax);
  });

  it('draws the login challenge with the lifetime and code count options.ts uses', () => {
    const seam = diagram('SecondFactorSeam');

    expect(ms(only(seam, /const CHALLENGE_TTL = '(\w+)';/u))).toBe(challengeTtlMs);
    expect(Number(only(seam, /const CHALLENGE_CODES = (\d+);/u))).toBe(challengeCodes);
  });

  it('draws the time steps with the period and drift totp.ts uses', () => {
    const steps = diagram('SecondFactorSteps');

    expect(Number(only(steps, /const STEP_SECONDS = (\d+);/u))).toBe(totpPeriod);
    expect(Number(only(steps, /const DRIFT_STEPS = (\d+);/u))).toBe(totpDrift);
  });

  it('writes out the email change defaults resolve-settings.ts uses', () => {
    expect<string>(emailChange.kind).toBe(read(SETTINGS, /config\.emailChange\?\.kind \?\? '(\w+)'/u));
    expect(ms(emailChange.ttl)).toBe(ms(changeTtl));
    expect(emailChange.digits).toBe(changeDigits);
    expect(emailChange.maxAttempts).toBe(changeAttempts);
    expect(ms(emailChange.revertTtl)).toBe(ms(revertTtl));
    expect(ms(emailChange.blockAfterRevert)).toBe(ms(blockAfterRevert));
    expect(ms(freshAuthAge)).toBe(ms(freshAuthDefault));
  });

  it('writes out the invitation defaults options.ts uses', () => {
    expect(ms(invitationLimits.ttl)).toBe(ms(inviteTtl));
    expect(String(invitationLimits.recheckInviter)).toBe(inviteRecheck);
    expect(String(invitationLimits.acceptWithoutSession)).toBe(inviteWithoutSession);

    for (const [mine, theirs] of [
      [invitationLimits.perInviter, invitePerInviter],
      [invitationLimits.perAddress, invitePerAddress],
      [invitationLimits.perIp, invitePerIp],
    ] as const) {
      expect([mine.limit, ms(mine.window)]).toEqual([theirs.limit, ms(theirs.window)]);
    }

    expect(ms(only(diagram('InvitationAccept'), /const MAX_TTL = '(\w+)';/u))).toBe(inviteMaxTtlMs);
  });
});
