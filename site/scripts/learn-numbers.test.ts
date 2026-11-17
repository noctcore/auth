// Keeps the numbers on the Learn pages tied to the code. Each fact below is a
// phrase a page must contain, built from the value the code uses: a constant
// read from the package source, or the answer of the public API. A changed
// default changes the phrase, and the page that still says the old value fails
// here. A page listed in PAGES may hold no other number: after the facts are
// taken out, any digit left (outside attack ids, algorithm names and the
// documentation IP ranges) fails too, so a new number cannot slip in unchecked.
//
// The pages also have to link the attack tests that cover them: every attack
// row in ATTACKS.md that names the page is linked from it, and every attack
// test a page links exists.
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  clientIp,
  createSessionCookie,
  DEFAULT_DOOR_LIMITS,
  generateNumericCode,
  generateToken,
  serializeCookie,
  sessionCookieName,
  TOKEN_BYTES,
  toMilliseconds,
  turnstile,
  type Duration,
} from '@noctcore/auth';
import { describe, expect, it } from 'bun:test';

const SITE = join(dirname(fileURLToPath(import.meta.url)), '..');
const REPO = join(SITE, '..');
const LEARN = join(SITE, 'src/content/docs/learn');
const AUTH_SRC = join(REPO, 'packages/auth/src');

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** The page's Markdown, frontmatter included. */
function page(slug: string): string {
  return readFileSync(join(LEARN, `${slug}.md`), 'utf8');
}

/** The source of a package file, relative to `packages/`. */
function source(path: string): string {
  return readFileSync(join(REPO, 'packages', path), 'utf8');
}

/**
 * The first capture of `pattern` in a package file. The pattern has to match
 * exactly once, so a renamed or duplicated constant fails loudly instead of
 * reading the wrong value.
 */
function read(path: string, pattern: RegExp): string {
  const matches = [...source(path).matchAll(new RegExp(pattern.source, `${pattern.flags}g`))];

  expect(matches.map((m) => m[0])).toHaveLength(1);

  return matches[0]?.[1] ?? '';
}

/** Every capture of `pattern` in a package file, which must agree on one value. */
function readAll(path: string, pattern: RegExp, count: number): string {
  const values = [...source(path).matchAll(new RegExp(pattern.source, `${pattern.flags}g`))].map(
    (m) => m[1] ?? '',
  );

  expect(values).toHaveLength(count);
  expect(new Set(values).size).toBe(1);

  return values[0] ?? '';
}

const num = (path: string, pattern: RegExp) => Number(read(path, pattern));

/** A duration in the unit the pages write it in. */
function minutes(duration: string | Duration): number {
  const ms = toMilliseconds(duration as Duration);

  expect(ms % MINUTE).toBe(0);

  return ms / MINUTE;
}

function inUnit(duration: string | Duration, unit: number): number {
  const ms = toMilliseconds(duration as Duration);

  expect(ms % unit).toBe(0);

  return ms / unit;
}

// Values from the code ------------------------------------------------------

const tokenHexLength = generateToken().length;

/** The code lengths generateNumericCode accepts. */
const codeDigits = Array.from({ length: 16 }, (_, digits) => digits).filter((digits) => {
  try {
    generateNumericCode(digits);

    return true;
  } catch {
    return false;
  }
});

const SETTINGS = 'auth/src/flows/resolve-settings.ts';
const defaultDigits = Number(readAll(SETTINGS, /\.digits \?\? (\d+)/u, 3));
const defaultAttempts = Number(readAll(SETTINGS, /\.maxAttempts \?\? (\d+)/u, 3));

/** The code lengths createAuth accepts in config, which must match what the generator draws. */
const configDigits = /digits < (\d+) \|\| digits > (\d+)\)/u.exec(source(SETTINGS));

/** The random id beside the HMAC in the lockout device cookie and the CSRF token. */
const signedIdBytes = Number(
  read('auth/src/throttle/device-token.ts', /encodeHexLowerCase\(randomBytes\((\d+), random\)\)/u),
);

const codeTtlMinutes = minutes(readAll(SETTINGS, /Kind === 'code' \? '(\w+)'/u, 3));

const TOTP = 'auth/src/plugins/two-factor/totp.ts';
const totpSecretBytes = num(TOTP, /export const TOTP_SECRET_BYTES = (\d+);/u);

const RECOVERY = 'auth/src/plugins/two-factor/recovery-codes.ts';
const recoveryCount = num(RECOVERY, /export const RECOVERY_CODE_COUNT = (\d+);/u);
const recoveryLength = num(RECOVERY, /const RECOVERY_CODE_LENGTH = (\d+);/u);
const recoveryAlphabet = read(RECOVERY, /const ALPHABET = '([0-9a-z]+)';/u).length;
const recoveryBits = recoveryLength * Math.log2(recoveryAlphabet);

const minSecretBytes = num('auth/src/crypto/keys.ts', /const MIN_SECRET_BYTES = (\d+);/u);

const TURNSTILE = 'auth/src/http/turnstile.ts';
const captchaTimeoutMs = num(TURNSTILE, /options\.timeoutMs \?\? (\d+);/u);
const captchaMaxToken = num(TURNSTILE, /const MAX_TOKEN_LENGTH = (\d+);/u);

const maxHops = Number(
  read('auth-nestjs/src/options.ts', /export const MAX_TRUSTED_HOPS = (\d+);/u),
);

const unsetHopsInDevelopment = num(
  'auth-nestjs/src/trust-proxy.ts',
  /if \(env\.NODE_ENV === 'production'\) \{[^}]*\}\s*return (\d+);/u,
);

const THROTTLE = 'auth/src/throttle/throttle.ts';
const perAccountIp = /windowRule\(lockout\.perAccountIp, (\d+), '(\w+)'\)/u;
const perAccount = /windowRule\(lockout\.perAccount, (\d+), '(\w+)'\)/u;

function rule(pattern: RegExp): { limit: number; minutes: number } {
  const match = pattern.exec(source(THROTTLE));

  expect(match).not.toBeNull();

  return { limit: Number(match?.[1]), minutes: minutes(match?.[2] ?? '') };
}

const SESSION = 'auth/src/session/session-manager.ts';
const absoluteTtlHours = inUnit(read(SESSION, /options\.absoluteTtl \?\? '(\w+)'/u), HOUR);
const rememberMeTtlDays = inUnit(read(SESSION, /options\.rememberMeTtl \?\? '(\w+)'/u), DAY);

const loginDoor = DEFAULT_DOOR_LIMITS.login;

/** The example X-Forwarded-For block on the trust proxy page, and what clientIp makes of it. */
function forwardedExample(hops: number): string {
  const text = page('trust-proxy-and-client-ips');
  const forwardedFor = /^X-Forwarded-For: (.+)$/mu.exec(text)?.[1];
  const remoteAddress = /^socket address: +(.+)$/mu.exec(text)?.[1];

  expect(forwardedFor).toBeDefined();
  expect(remoteAddress).toBeDefined();

  return clientIp({ remoteAddress, forwardedFor, trustedHops: hops }) ?? '';
}

// The facts -----------------------------------------------------------------

const PAGES: Record<string, readonly string[]> = {
  'entropy-and-tokens': [
    `${TOKEN_BYTES} bytes from the platform's secure random source`,
    `fills ${TOKEN_BYTES} bytes`,
    `writes them as ${tokenHexLength} lowercase hex characters`,
    `exactly ${tokenHexLength} lowercase hex characters`,
    `${TOKEN_BYTES * 8} bits, far beyond what any`,
    `random id of ${signedIdBytes} bytes (${signedIdBytes * 8} bits)`,
    `${defaultDigits} digits by default (${codeDigits[0]} to ${codeDigits.at(-1)} allowed)`,
    `each code gets ${defaultAttempts} attempts by default`,
    `lives ${codeTtlMinutes} minutes by default`,
    `TOTP secrets are ${totpSecretBytes} bytes (${totpSecretBytes * 8} bits)`,
    `${recoveryCount} codes of ${recoveryLength} characters each from a ${recoveryAlphabet}-symbol alphabet, ${recoveryBits} bits per code`,
    `at least ${minSecretBytes} bytes`,
    `a ${minSecretBytes}-character sentence`,
    `openssl rand -hex ${minSecretBytes}`,
    `a ${TOKEN_BYTES}-byte session secret`,
  ],
  'why-tokens-are-hashed': [
    `A ${TOKEN_BYTES}-byte random token`,
    `with ${defaultDigits} digits by default`,
  ],
  captcha: [`within ${captchaTimeoutMs} ms`, `longer than ${captchaMaxToken} characters`],
  'trust-proxy-and-client-ips': [
    'With 0 trusted hops the header is ignored',
    `With 1 trusted hop the client IP is \`${forwardedExample(1)}\``,
    `With 0 trusted hops it is \`${forwardedExample(0)}\``,
    `With 2 trusted hops it is \`${forwardedExample(2)}\``,
    `from 0 to ${maxHops}`,
    `unset is ${unsetHopsInDevelopment} in development`,
    `login allows ${loginDoor.limit} attempts per ${minutes(loginDoor.window) === 1 ? 'minute' : `${minutes(loginDoor.window)} minutes`} from one IP`,
    `(${rule(perAccountIp).limit} attempts per ${rule(perAccountIp).minutes} minutes)`,
    `(${rule(perAccount).limit} attempts per ${rule(perAccount).minutes} minutes from all sources)`,
  ],
  'cookies-and-desktop-shells': [
    `after ${absoluteTtlHours} hours by default`,
    `${rememberMeTtlDays} days by default`,
  ],
};

/** What may hold a digit on a checked page without being a fact. */
const NOT_NUMBERS = [
  /\]\([^)]*\)/gu, // link targets
  /\bA\d{3}\b/gu, // attack ids
  /\bHMAC-SHA-256\b|\bSHA-256\b/gu,
  /\b(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}\b/gu, // documentation ranges (RFC 5737)
];

/** The facts a page does not state. A fact listed twice must appear twice. */
function missingFacts(text: string, facts: readonly string[]): string[] {
  return facts.filter((fact, i) => {
    const wanted = facts.slice(0, i + 1).filter((f) => f === fact).length;

    return text.split(fact).length - 1 < wanted;
  });
}

/**
 * The lines that still hold a digit once each listed fact is taken out once
 * (and only once, so a fact phrase repeated in another sentence leaves its
 * number behind) and the allowed non-numbers are removed.
 */
function strayLines(text: string, facts: readonly string[]): string[] {
  let rest = text;

  // Longest first, so a fact inside a longer one does not leave pieces behind.
  for (const fact of [...facts].sort((a, b) => b.length - a.length)) rest = rest.replace(fact, ' ');
  for (const pattern of NOT_NUMBERS) rest = rest.replace(pattern, ' ');

  return rest.split('\n').filter((line) => /\d/u.test(line));
}

describe('Learn page numbers', () => {
  for (const [slug, facts] of Object.entries(PAGES)) {
    it(`${slug} states the values the code uses`, () => {
      expect(missingFacts(page(slug), facts)).toEqual([]);
    });

    it(`${slug} holds no number that is not checked here`, () => {
      expect(strayLines(page(slug), facts)).toEqual([]);
    });
  }

  it('catches a checked number reused in a sentence the facts do not cover', () => {
    const slug = 'entropy-and-tokens';
    const facts = PAGES[slug] ?? [];
    const tampered = `${page(slug)}\nRecovery codes get 5 attempts, and a TOTP secret has 256 bits.\n`;

    expect(strayLines(tampered, facts)).toEqual([
      'Recovery codes get 5 attempts, and a TOTP secret has 256 bits.',
    ]);
  });

  it('allows in config the code lengths the generator draws', () => {
    expect(configDigits).not.toBeNull();
    expect([Number(configDigits?.[1]), Number(configDigits?.[2])]).toEqual([
      codeDigits[0] ?? -1,
      codeDigits.at(-1) ?? -1,
    ]);
  });

  it('gives the CSRF token the same random id length as the device cookie', () => {
    expect(
      Number(read('auth/src/http/csrf.ts', /encodeHexLowerCase\(randomBytes\((\d+), random\)\)/u)),
    ).toBe(signedIdBytes);
  });

  it('reads the hop limit the same in both adapters', () => {
    expect(
      Number(read('auth-trpc/src/options.ts', /export const MAX_TRUSTED_HOPS = (\d+);/u)),
    ).toBe(maxHops);
  });

  it('ignores X-Forwarded-For with no trusted hop', () => {
    expect(
      clientIp({ remoteAddress: '203.0.113.9', forwardedFor: '192.0.2.66', trustedHops: 0 }),
    ).toBe('203.0.113.9');
  });

  it('rejects an oversized captcha token without asking the provider, and only then', async () => {
    let calls = 0;

    const verifier = turnstile({
      secret: 'turnstile-test-secret',
      fetch: (async () => {
        calls += 1;

        return new Response(JSON.stringify({ success: true }));
      }) as unknown as typeof fetch,
    });

    expect(await verifier.verify('x'.repeat(captchaMaxToken + 1), { door: 'login' })).toBe(
      'reject',
    );
    expect(calls).toBe(0);
    expect(await verifier.verify('x'.repeat(captchaMaxToken), { door: 'login' })).toBe('pass');
    expect(calls).toBe(1);
  });
});

describe('Learn page cookie facts', () => {
  const text = page('cookies-and-desktop-shells');

  it('shows the default session cookie exactly as serializeCookie writes it', () => {
    const header = serializeCookie(
      createSessionCookie({}, 'TOKEN', { expiresAt: DAY, persistent: false, now: 0 }),
    ).replace('TOKEN', '<token>');

    expect(text).toContain(`Set-Cookie: ${header}`);
    expect(text).toContain(`named \`${sessionCookieName()}\` by default`);
  });

  it('names the cookies the code sets', () => {
    expect(source('auth/src/http/cookie.ts')).toContain("prefixedCookieName(config, 'device')");
    expect(text).toContain('`__Host-device`');

    const trusted = read(
      'auth/src/plugins/two-factor/trusted-devices.ts',
      /export const TRUSTED_DEVICE_COOKIE = '([a-z-]+)';/u,
    );

    expect(text).toContain(`\`__Host-${trusted}\``);

    for (const adapter of ['auth-nestjs', 'auth-trpc']) {
      const options = source(`${adapter}/src/options.ts`);

      expect(options).toContain("secure ? '__Host-csrf' : 'csrf'");
      expect(options).toContain("secure ? '__Host-presession' : 'presession'");
    }

    expect(text).toContain('`__Host-csrf` and `__Host-presession`');
  });

  it('refuses SameSite=None without Secure when a cookie is built, not when the name is checked', () => {
    const config = { secure: false, sameSite: 'none' } as const;

    expect(() => sessionCookieName(config)).not.toThrow();
    expect(() =>
      createSessionCookie(config, 'TOKEN', { expiresAt: DAY, persistent: false, now: 0 }),
    ).toThrow('SameSite=None requires a Secure cookie');
  });

  it('keeps the adapter CSRF cookies at SameSite=Lax', () => {
    for (const adapter of ['auth-nestjs', 'auth-trpc']) {
      const csrf = source(`${adapter}/src/csrf-tokens.ts`);

      expect(csrf.match(/sameSite: '(\w+)'/gu)).toEqual(["sameSite: 'lax'", "sameSite: 'lax'"]);
    }
  });
});

describe('Learn page attack links', () => {
  const index = readFileSync(join(AUTH_SRC, '../tests/attacks/ATTACKS.md'), 'utf8');
  const LINK =
    /\[(A\d{3})[^\]]*\]\(https:\/\/github\.com\/noctcore\/auth\/blob\/main\/(packages\/[a-z-]+\/tests\/attacks\/(A\d{3})-[a-z0-9-]+\.test\.ts)\)/gu;

  for (const slug of Object.keys(PAGES)) {
    const text = page(slug);
    const title = /^title: (.+)$/mu.exec(text)?.[1] ?? '';
    const links = [...text.matchAll(LINK)];

    it(`${slug} links attack tests that exist`, () => {
      expect(links.length).toBeGreaterThan(0);

      for (const [, label, path, id] of links) {
        expect(label).toBe(id);
        expect(existsSync(join(REPO, path ?? ''))).toBe(true);
      }
    });

    it(`${slug} links every attack ATTACKS.md files under it`, () => {
      const named = [...index.matchAll(/^\| (A\d{3}) \| [^|]+ \| ([^|]+) \|/gmu)]
        .filter(([, , pages = '']) => pages.split(';').some((p) => p.trim() === title))
        .map(([, id]) => id);
      const linked = new Set(links.map(([, id]) => id));

      expect(named.length).toBeGreaterThan(0);
      expect(named.filter((id) => !linked.has(id))).toEqual([]);
    });
  }
});
