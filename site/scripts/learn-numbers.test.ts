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
//
// Some pages draw their numbers in a diagram from the code sample beside it
// (snippets/learn/). Those samples are checked here against the source too,
// so the page, the sample and the diagram cannot drift apart.
import { createHash } from 'node:crypto';
import {
  clientIp,
  createSessionCookie,
  DEFAULT_DOOR_LIMITS,
  TRUST_PROXY_PRESETS,
  generateNumericCode,
  generateToken,
  serializeCookie,
  sessionCookieName,
  TOKEN_BYTES,
  turnstile,
  type Duration,
} from '@noctcore/auth';
import { describe, expect, it } from 'bun:test';
import { lockout } from '../snippets/learn/lockout';
import { session } from '../snippets/learn/session';
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

/** A duration in whole minutes. */
const minutes = (duration: string | Duration) => inUnit(duration, MINUTE);

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
const absoluteTtl = read(SESSION, /options\.absoluteTtl \?\? '(\w+)'/u);
const rememberMeTtl = read(SESSION, /options\.rememberMeTtl \?\? '(\w+)'/u);
const absoluteTtlHours = inUnit(absoluteTtl, HOUR);
const rememberMeTtlDays = inUnit(rememberMeTtl, DAY);
const touchInterval = read(SESSION, /options\.touchInterval \?\? '(\w+)'/u);
const idleDefaults = /rememberMe \? '(\w+)' : '(\w+)'/u.exec(source(SESSION));
const idleRemembered = idleDefaults?.[1] ?? '';
const idleTimeout = idleDefaults?.[2] ?? '';
const maxPerUser = num(SESSION, /options\.maxPerUser === undefined \? (\d+)/u);
const freshAuthAge = read(SETTINGS, /freshAuthAge \?\? '(\w+)'/u);

/** The lockout defaults, as throttle.ts reads them. */
const lockoutDefault = (name: string) => read(THROTTLE, new RegExp(`lockout\\.${name} \\?\\? '(\\w+)'`, 'u'));
const baseLock = lockoutDefault('baseLock');
const maxLock = lockoutDefault('maxLock');
const quietPeriod = lockoutDefault('quietPeriod');
const deviceMaxAge = lockoutDefault('deviceMaxAge');
const lockFactor = num(THROTTLE, /this\.baseLockMs \* (\d+) \*\* Math\.min/u);
const perDevice = /windowRule\(lockout\.perDevice, (\d+), '(\w+)'\)/u;
const revealLocked = read(THROTTLE, /lockout\.revealLocked \?\? (\w+);/u);

const CSRF = 'auth/src/http/csrf.ts';
const csrfNonceHex = num(CSRF, /const NONCE = \/\^\[0-9a-f\]\{(\d+)\}\$\/u;/u);
const csrfSecretBytes = num(CSRF, /export const MIN_CSRF_SECRET_BYTES = (\d+);/u);

/** A session handle is the HMAC-SHA-256 of the store key in unpadded base64url. */
const handleLength = Math.ceil((createHash('sha256').digest().length * 8) / 6);
const storeKeyLength = createHash('sha256').digest('hex').length;

const loginDoor = DEFAULT_DOOR_LIMITS.login;

/** The |t| threshold the timing comparison uses (dudect's). */
const timingThreshold = Number(
  read('auth/tests/timing/compare.ts', /const THRESHOLD = ([\d.]+);/u),
);

/** The Express presets as the trust proxy page lists them, from the ranges the code expands them to. */
const presetRanges = (() => {
  const items = Object.entries(TRUST_PROXY_PRESETS).map(
    ([name, ranges]) => `\`${name}\` (${ranges.map((r) => `\`${r}\``).join(', ')})`,
  );

  return `${items.slice(0, -1).join(', ')} and ${items.at(-1) ?? ''}`;
})();

/** The example X-Forwarded-For block on the trust proxy page, and what clientIp makes of it. */
function forwardedExample(hops: number): string {
  const text = page('trust-proxy-and-client-ips');
  const forwardedFor = /^X-Forwarded-For: (.+)$/mu.exec(text)?.[1];
  const remoteAddress = /^socket address: +(.+)$/mu.exec(text)?.[1];

  expect(forwardedFor).toBeDefined();
  expect(remoteAddress).toBeDefined();

  return clientIp({ remoteAddress, forwardedFor, trustedHops: hops }) ?? '';
}

/** A forwarded entry and the address clientIp reads from it, as the trust proxy page writes them. */
function forwardedEntry(written: string): string {
  const read = clientIp({ remoteAddress: '10.0.0.2', forwardedFor: written, trustedHops: 1 });

  return `\`${written}\` is \`${read ?? ''}\``;
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
  enumeration: [
    // A wall-clock measurement on one laptop, not a constant: listed so that
    // no other number can slip onto the page unchecked.
    'The taken path about 4.5 ms slower',
    `(\\|t\\| under ${timingThreshold}, on a heavily loaded machine)`,
  ],
  'revocation-races': [],
  captcha: [`within ${captchaTimeoutMs} ms`, `longer than ${captchaMaxToken} characters`],
  'trust-proxy-and-client-ips': [
    'With 0 trusted hops the header is ignored',
    `With 1 trusted hop the client IP is \`${forwardedExample(1)}\``,
    `With 0 trusted hops it is \`${forwardedExample(0)}\``,
    `With 2 trusted hops it is \`${forwardedExample(2)}\``,
    `strips a port (${forwardedEntry('203.0.113.9:51234')})`,
    `brackets (${forwardedEntry('[2001:db8::1]:443')})`,
    `an IPv6 zone id (${forwardedEntry('fe80::1%eth0')})`,
    `from 0 to ${maxHops}`,
    `the Express presets ${presetRanges}, the same ranges Express gives them`,
    `unset is ${unsetHopsInDevelopment} in development`,
    `login allows ${loginDoor.limit} attempts per ${minutes(loginDoor.window) === 1 ? 'minute' : `${minutes(loginDoor.window)} minutes`} from one IP`,
    `(${rule(perAccountIp).limit} attempts per ${rule(perAccountIp).minutes} minutes)`,
    `(${rule(perAccount).limit} attempts per ${rule(perAccount).minutes} minutes from all sources)`,
  ],
  'cookies-and-desktop-shells': [
    `after ${absoluteTtlHours} hours by default`,
    `${rememberMeTtlDays} days by default`,
  ],
  csrf: [`the nonce is ${csrfNonceHex} hex characters`, `at least ${csrfSecretBytes} bytes`],
  'brute-force-and-lockout': [
    `${rule(perAccountIp).limit} attempts per ${rule(perAccountIp).minutes} minutes`,
    `${rule(perAccount).limit} attempts per ${rule(perAccount).minutes} minutes from all sources`,
    `locks the account for ${minutes(baseLock)} minutes, then ${minutes(baseLock) * lockFactor}, then ${minutes(baseLock) * lockFactor ** 2}, capped at ${inUnit(maxLock, HOUR)} hour`,
    `renews a ${inUnit(quietPeriod, HOUR)}-hour quiet period`,
    `resets the backoff to ${minutes(baseLock)} minutes`,
    `(${rule(perDevice).limit} per ${rule(perDevice).minutes} minutes each)`,
    `once the devices together hold ${rule(perDevice).limit} slots`,
    `older than ${inUnit(deviceMaxAge, DAY)} days`,
    `generous (${loginDoor.limit} a minute)`,
  ],
  'sessions-and-expiry': [
    `carries ${TOKEN_BYTES} bytes`,
    `${TOKEN_BYTES * 8} bits of entropy`,
    `${absoluteTtlHours} hours, ${rememberMeTtlDays} days with remember me`,
    `${minutes(idleTimeout)} minutes, ${inUnit(idleRemembered, DAY)} days with remember me`,
    `(${maxPerUser} by default)`,
    `as ${handleLength} characters of unpadded base64url`,
    `the ${storeKeyLength}-character hex shape`,
    `the default idle timeout is ${minutes(idleTimeout)} minutes`,
    `(within ${minutes(freshAuthAge)} minutes)`,
  ],
};

describe('Learn page numbers', () => {
  numberTests(PAGES);

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

    // Both adapters name their CSRF cookies through the core's resolveCsrfSettings.
    const csrfSettings = source('auth/src/http/csrf-adapter.ts');

    expect(csrfSettings).toContain("secure ? '__Host-csrf' : 'csrf'");
    expect(csrfSettings).toContain("secure ? '__Host-presession' : 'presession'");

    for (const adapter of ['auth-nestjs', 'auth-trpc']) {
      expect(source(`${adapter}/src/options.ts`)).toContain('resolveCsrfSettings(csrf, secure)');
    }

    expect(text).toContain('`__Host-csrf` and `__Host-presession`');
  });

  it('refuses a fixed SameSite=None without Secure at startup, a function when a cookie is built', () => {
    const fixed = { secure: false, sameSite: 'none' } as const;
    const chosen = { secure: false, sameSite: (): 'none' => 'none' };

    expect(() => sessionCookieName(fixed)).not.toThrow();
    expect(() =>
      createSessionCookie(fixed, 'TOKEN', { expiresAt: DAY, persistent: false, now: 0 }),
    ).toThrow('SameSite=None requires a Secure cookie');
    expect(() =>
      createSessionCookie(chosen, 'TOKEN', { expiresAt: DAY, persistent: false, now: 0 }),
    ).toThrow('SameSite=None requires a Secure cookie');
    expect(text).toContain('when `createAuth` starts');
  });

  it('gives the adapter CSRF cookies the session cookie SameSite, never a fixed one', () => {
    // One implementation in the core, used by both adapters.
    const csrf = source('auth/src/http/csrf-adapter.ts');

    expect(csrf.match(/sameSite: '(\w+)'/gu)).toBeNull();
    expect(csrf.match(/secure: options\.secure, sameSite, path/gu)).toHaveLength(2);

    expect(text).toContain("CSRF and pre-session cookies and the blank cookie");
    expect(text).toContain('`resolveSameSite`');
  });
});

describe('Learn page attack links', () => {
  attackLinkTests(Object.keys(PAGES));
});

describe('Learn code samples and diagrams', () => {
  it('writes out the lockout defaults throttle.ts uses', () => {
    for (const [name, pattern] of [
      ['perAccountIp', perAccountIp],
      ['perAccount', perAccount],
      ['perDevice', perDevice],
    ] as const) {
      const { limit, minutes: window } = rule(pattern);

      expect([lockout[name].limit, ms(lockout[name].window)]).toEqual([limit, window * MINUTE]);
    }

    expect(ms(lockout.baseLock)).toBe(ms(baseLock));
    expect(ms(lockout.maxLock)).toBe(ms(maxLock));
    expect(ms(lockout.quietPeriod)).toBe(ms(quietPeriod));
    expect(ms(lockout.deviceMaxAge)).toBe(ms(deviceMaxAge));
    expect(String(lockout.revealLocked)).toBe(revealLocked);
  });

  it('draws each new lock with the factor throttle.ts uses', () => {
    expect(Number(only(diagram('LockoutLocks'), /const LOCK_FACTOR = (\d+);/u))).toBe(lockFactor);
  });

  it('writes out the session defaults session-manager.ts uses', () => {
    expect(ms(session.absoluteTtl)).toBe(ms(absoluteTtl));
    expect(ms(session.rememberMeTtl)).toBe(ms(rememberMeTtl));
    expect(ms(session.idleTimeout({ rememberMe: false, attributes: undefined }))).toBe(
      ms(idleTimeout),
    );
    expect(ms(session.idleTimeout({ rememberMe: true, attributes: undefined }))).toBe(
      ms(idleRemembered),
    );
    expect(ms(session.touchInterval)).toBe(ms(touchInterval));
    expect(session.maxPerUser).toBe(maxPerUser);
  });

  it('says "once a minute" and "a minute" only where the code means one minute', () => {
    expect(ms(touchInterval)).toBe(MINUTE);
    expect(ms(loginDoor.window)).toBe(MINUTE);
  });
});
