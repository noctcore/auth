// Keeps the configuration reference tied to the code. Its tables are drawn
// from src/components/reference/config-keys.ts, so this reads that module:
// every row's default must equal the value built here from the package source
// (a constant read with the Learn readers, or the public API's answer), every
// row must be listed here, so a new row cannot slip in unchecked, and a digit
// in a description must be one of the facts below. The full example
// (snippets/reference/config.ts) is checked against the same values, and the
// page itself must state the startup refusals with the numbers the code uses.
import { DEFAULT_DOOR_LIMITS, TOKEN_BYTES, type Mailer } from '@noctcore/auth';
import { describe, expect, it } from 'bun:test';
import { readFileSync } from 'node:fs';
import ts from 'typescript';
import { join } from 'node:path';
import * as keys from '../src/components/reference/config-keys';
import { authConfig } from '../snippets/reference/config';
import { DAY, missingFacts, num, read, readAll, SITE, source } from './learn-checks';

type Row = keys.ConfigRow;

/** A code chip of a string default: `'24h'`. */
const str = (value: string) => `\`'${value}'\``;
/** A code chip of a literal default: `12`, `true`. */
const lit = (value: string | number | boolean) => `\`${value}\``;
const rule = (limit: number, window: string) => `${limit} per ${str(window)}`;

// Values from the code ------------------------------------------------------

const POLICY = 'auth/src/password/policy.ts';
const policyDefaults =
  /DEFAULT_PASSWORD_POLICY: PasswordPolicy = \{ minLength: (\d+), maxLength: (\d+) \}/u.exec(
    source(POLICY),
  );
const minLength = Number(policyDefaults?.[1]);
const maxLength = Number(policyDefaults?.[2]);
const CREATE = 'auth/src/create-auth.ts';
const minConfigurableLength = num(CREATE, /policy\.minLength < (\d+)\)/u);
const minSecretBytes = num('auth/src/crypto/keys.ts', /const MIN_SECRET_BYTES = (\d+);/u);

const BREACH = 'auth/src/password/breach.ts';
const breachTimeout = num(BREACH, /options\.timeoutMs \?\? (\d+);/u);
const breachUserAgent = read(BREACH, /options\.userAgent \?\? '([^']+)';/u);
const breachBaseUrl = read(BREACH, /options\.baseUrl \?\? '([^']+)';/u);

const SESSION = 'auth/src/session/session-manager.ts';
const sessionDefault = (name: string) =>
  read(SESSION, new RegExp(`options\\.${name},\\s*'(\\w+)'`, 'u'));
const absoluteTtl = sessionDefault('absoluteTtl');
const rememberMeTtl = sessionDefault('rememberMeTtl');
const touchInterval = sessionDefault('touchInterval');
const idleDefaults = /rememberMe \? '(\w+)' : '(\w+)'/u.exec(source(SESSION));
const idleRemembered = idleDefaults?.[1] ?? '';
const idleTimeout = idleDefaults?.[2] ?? '';
const maxPerUser = num(SESSION, /options\.maxPerUser === undefined \? (\d+)/u);

const SETTINGS = 'auth/src/flows/resolve-settings.ts';
const setting = (pattern: string) => read(SETTINGS, new RegExp(pattern, 'u'));
const freshAuthAge = setting(`freshAuthAge,\\s*'(\\w+)'`);
const digits = Number(readAll(SETTINGS, /\.digits \?\? (\d+)/u, 3));
const maxAttempts = Number(readAll(SETTINGS, /\.maxAttempts \?\? (\d+)/u, 3));
const digitRange = /digits < (\d+) \|\| digits > (\d+)\)/u.exec(source(SETTINGS));
const minDigits = Number(digitRange?.[1]);
const maxDigits = Number(digitRange?.[2]);
/** The default TTL of each kind, from `kind === 'code' ? '15m' : '24h'`. */
function kindTtls(kind: string): { code: string; link: string } {
  const match = new RegExp(`${kind} === 'code' \\? '(\\w+)' : '(\\w+)'`, 'u').exec(
    source(SETTINGS),
  );

  expect(match).not.toBeNull();

  return { code: match?.[1] ?? '', link: match?.[2] ?? '' };
}
const verificationTtl = kindTtls('verificationKind');
const resetTtl = kindTtls('resetKind');
const changeTtl = kindTtls('changeKind');
const minRevertMs = setting('MIN_REVERT_TTL_MS = ([\\d* ]+);')
  .split('*')
  .reduce((product, factor) => product * Number(factor), 1);
const minRevertDays = minRevertMs / DAY;

const COOKIE = 'auth/src/http/cookie.ts';
const cookieName = read(COOKIE, /const base = config\.name \?\? '(\w+)';/u);
const cookieSecure = readAll(COOKIE, /config\.secure \?\? (\w+)\)?/u, 4);
const cookieSameSite = read(COOKIE, /config\.sameSite \?\? '(\w+)'/u);

const defaultPolicy = read(
  'auth/src/shared/email.ts',
  /if \(option === undefined\) return (\w+)Policy;/u,
);

const THROTTLE = 'auth/src/throttle/throttle.ts';
function windowRule(name: string): string {
  const match = new RegExp(`windowRule\\(name\\('${name}'\\), options\\.${name}, (\\d+), '(\\w+)'\\)`, 'u').exec(
    source(THROTTLE),
  );

  expect(match).not.toBeNull();

  return rule(Number(match?.[1]), match?.[2] ?? '');
}
const lockoutDefault = (name: string) =>
  read(THROTTLE, new RegExp(`options\\.${name},\\s*'(\\w+)'`, 'u'));
const lockFactor = num(THROTTLE, /this\.baseLockMs \* (\d+) \*\* Math\.min/u);
const permanentDevices = read(THROTTLE, /options\.permanent\?\.trustedDevices \?\? (\w+);/u);
const revealLocked = read(THROTTLE, /options\.revealLocked \?\? (\w+);/u);
const countSuccesses = read(THROTTLE, /options\.countSuccesses \?\? (\w+);/u);
const sessionProofs = read(THROTTLE, /options\.sessionProofs \?\? '(\w+)';/u);
const minAfterLocks = num(THROTTLE, /afterLocks < (\d+)\)/u);

const turnstileTimeout = num('auth/src/http/turnstile.ts', /options\.timeoutMs \?\? (\d+);/u);

const ARGON = 'auth/src/password/argon2.ts';
const argon = (name: string) =>
  num(ARGON, new RegExp(`DEFAULT_ARGON2ID = \\{[^}]*${name}: ([\\d_]+)`, 'u'));
const owaspTimeCost = num(ARGON, /OWASP_ARGON2ID = \{[^}]*timeCost: (\d+)/u);
const memoryCost = Number(
  read(ARGON, /DEFAULT_ARGON2ID = \{[^}]*memoryCost: ([\d_]+)/u).replaceAll('_', ''),
);

const REDIS = 'auth-redis/src/session-store.ts';
const redisPrefix = read(REDIS, /options\.prefix \?\? '([^']+)'/u);
const redisMaxSessionTtl = read(REDIS, /options\.maxSessionTtl \?\? '(\w+)'/u);
const redisEpochTtl = read(REDIS, /options\.epochTtl \?\? '(\w+)'/u);

const PRISMA = 'auth-prisma/src/user-store.ts';
const prismaFields = ['id', 'email', 'emailVerified', 'passwordHash']
  .map((field) => read(PRISMA, new RegExp(`${field}: fields\\.${field} \\?\\? '(\\w+)'`, 'u')))
  .concat(read(PRISMA, /deletedAt: fields\.deletedAt === undefined \? '(\w+)'/u));

/** The adapters resolve `touch` left out to a predicate that says yes: `true`. */
const touchDefault = (path: string) =>
  read(path, /if \(touch === undefined \|\| touch === true\) return \(\) => (true);/u);

// What create-auth.ts falls back to for each collaborator.
const fallback = (name: string) => read(CREATE, new RegExp(`config\\.${name} \\?\\? (\\w+);`, 'u'));

// The defaults ----------------------------------------------------------------

/** Each table's rows with the default they must show, by row id. */
const EXPECTED: Record<string, Record<string, string>> = {
  essentials: {
    stores: 'required',
    'password-hasher': 'required',
    secret: 'required',
    mailer: 'required',
    'urls-resetpassword': 'none',
    'password-breachcheck': 'none',
    'session-cookie-secure': lit(cookieSecure),
  },
  required: {
    'stores-users': 'required',
    'stores-tokens': 'required',
    'stores-sessions': 'required',
    'stores-counters': 'required',
    'password-hasher': 'required',
    secret: 'required',
    mailer: 'required',
  },
  password: {
    'password-policy-minlength': lit(minLength),
    'password-policy-maxlength': lit(maxLength),
    'password-breachcheck': 'none',
  },
  pwnedPasswordsOptions: {
    'pwnedpasswords-timeoutms': lit(breachTimeout),
    'pwnedpasswords-fetch': 'global `fetch`',
    'pwnedpasswords-useragent': str(breachUserAgent),
    'pwnedpasswords-baseurl': str(breachBaseUrl),
    'pwnedpasswords-onresult': 'none',
    'pwnedpasswords-logger': 'silent',
  },
  session: {
    'session-absolutettl': str(absoluteTtl),
    'session-remembermettl': str(rememberMeTtl),
    'session-idletimeout': `${str(idleTimeout)}, or ${str(idleRemembered)} with "remember me"`,
    'session-touchinterval': str(touchInterval),
    'session-maxperuser': lit(maxPerUser),
    'session-attributes': 'none',
    'session-freshauthage': str(freshAuthAge),
  },
  sessionCookie: {
    'session-cookie-name': str(cookieName),
    'session-cookie-secure': lit(cookieSecure),
    'session-cookie-samesite': str(cookieSameSite),
  },
  email: { 'email-normalize': str(defaultPolicy) },
  registration: {
    'registration-revealexisting': lit(setting('revealExisting \\?\\? (\\w+)')),
    'registration-autologin': lit(setting('autoLogin \\?\\? (\\w+)')),
  },
  emailVerification: {
    'emailverification-kind': str(
      setting("verificationKind = config\\.emailVerification\\?\\.kind \\?\\? '(\\w+)'"),
    ),
    'emailverification-ttl': `${str(verificationTtl.code)} for codes, ${str(verificationTtl.link)} for links`,
    'emailverification-digits': lit(digits),
    'emailverification-maxattempts': lit(maxAttempts),
    'emailverification-linkwithoutsession': lit(setting('linkWithoutSession \\?\\? (\\w+);')),
  },
  passwordReset: {
    'passwordreset-kind': str(
      setting("resetKind = config\\.passwordReset\\?\\.kind \\?\\? '(\\w+)'"),
    ),
    'passwordreset-ttl': `${str(resetTtl.link)} for links, ${str(resetTtl.code)} for codes`,
    'passwordreset-digits': lit(digits),
    'passwordreset-maxattempts': lit(maxAttempts),
    'passwordreset-ticketttl': str(setting("ticketTtl,\\s*'(\\w+)'")),
    'passwordreset-enqueue': 'none',
    'passwordreset-markemailverified': lit(setting('markEmailVerified \\?\\? (\\w+)')),
  },
  emailChange: {
    'emailchange-kind': str(setting("changeKind = config\\.emailChange\\?\\.kind \\?\\? '(\\w+)'")),
    'emailchange-ttl': `${str(changeTtl.code)} for codes, ${str(changeTtl.link)} for links`,
    'emailchange-digits': lit(digits),
    'emailchange-maxattempts': lit(maxAttempts),
    'emailchange-revertttl': str(setting("revertTtl,\\s*'(\\w+)'")),
    'emailchange-blockafterrevert': str(setting("blockAfterRevert,\\s*'(\\w+)'")),
  },
  urls: {
    'urls-verifyemail': 'none',
    'urls-resetpassword': 'none',
    'urls-confirmemailchange': 'none',
    'urls-revertemailchange': 'none',
  },
  lockout: {
    'throttle-lockout-peraccountip': windowRule('perAccountIp'),
    'throttle-lockout-peraccount': windowRule('perAccount'),
    'throttle-lockout-baselock': str(lockoutDefault('baseLock')),
    'throttle-lockout-maxlock': str(lockoutDefault('maxLock')),
    'throttle-lockout-durations': 'none',
    'throttle-lockout-quietperiod': str(lockoutDefault('quietPeriod')),
    'throttle-lockout-perdevice': windowRule('perDevice'),
    'throttle-lockout-devicemaxage': str(lockoutDefault('deviceMaxAge')),
    'throttle-lockout-permanent': 'off',
    'throttle-lockout-permanent-trusteddevices': lit(permanentDevices),
    'throttle-lockout-reveallocked': lit(revealLocked),
    'throttle-lockout-countsuccesses': lit(countSuccesses),
    'throttle-lockout-sessionproofs': str(sessionProofs),
  },
  doors: Object.fromEntries(
    Object.entries(DEFAULT_DOOR_LIMITS).map(([door, r]) => [
      keys.rowId(door, 'throttle-doors'),
      rule(r.limit, String(r.window)),
    ]),
  ),
  collaborators: {
    captcha: 'none',
    audit: 'none',
    hooks: 'none',
    plugins: lit(read(CREATE, /config\.plugins \?\? (\[\])\)/u)),
    logger: fallback('logger') === 'silentLogger' ? 'silent' : '',
    metrics: fallback('metrics') === 'noopMetrics' ? 'no-op' : '',
    'background-waituntil': 'none',
    'background-timeout': 'none',
    'background-maxpending': 'none',
    clock: fallback('clock') === 'systemClock' ? 'system clock' : '',
    random:
      /globalThis\.crypto\.getRandomValues/u.test(source('auth/src/crypto/random.ts')) &&
      fallback('random') === 'cryptoRandom'
        ? '`crypto.getRandomValues`'
        : '',
  },
  turnstileOptions: {
    'turnstile-secret': 'required',
    'turnstile-expectedhostnames': 'none',
    'turnstile-checkaction': 'off',
    'turnstile-timeoutms': lit(turnstileTimeout),
    'turnstile-fetch': 'global `fetch`',
    'turnstile-onresult': 'none',
    'turnstile-logger': 'silent',
  },
  argon2idOptions: {
    'argon2id-memorycost': `${lit(memoryCost)} (${Math.round(memoryCost / 1024)} MiB)`,
    'argon2id-timecost': lit(argon('timeCost')),
    'argon2id-parallelism': lit(argon('parallelism')),
    'argon2id-secret': 'none',
    'argon2id-unsafeallowweakparameters': lit(false),
  },
  rotation: {
    previoussecret: 'none',
  },
  nestjsAdapterOptions: {
    'nestjs-authmodule-touch': lit(touchDefault('auth-nestjs/src/options.ts')),
  },
  trpcAdapterOptions: {
    'trpc-createauthcontext-touch': lit(touchDefault('auth-trpc/src/options.ts')),
    'trpc-createauthcontext-meta-touch': 'none',
  },
  csrfHandout: {
    'csrf-handout-sessioncookies-csrftoken-request-response': 'none',
    'csrf-handout-ctx-auth-csrftoken': 'none',
    'csrf-handout-authresponsemeta-responsemeta': 'none',
  },
  redisStoresOptions: {
    'redisstores-prefix': str(redisPrefix),
    'redisstores-maxsessionttl': str(redisMaxSessionTtl),
    'redisstores-epochttl': str(redisEpochTtl),
    'redisstores-clock': 'system clock',
  },
  legacySessionsOptions: {
    'adoptlegacysessions-take': 'required',
    'adoptlegacysessions-maxttl': 'required',
    'adoptlegacysessions-clock': 'system clock',
    'adoptlegacysessions-logger': 'none',
  },
  prismaStoresOptions: {
    'prismastores-delegate': 'required',
    'prismastores-tokendelegate': 'required',
    'prismastores-fields': prismaFields.map((f) => lit(f)).join(', '),
    'prismastores-select': 'none',
    'prismastores-touser': 'the four auth fields',
    'prismastores-createdata': 'none',
    'prismastores-writewhere': 'none',
  },
};

/** The id prefix each option table is drawn with on the page. */
const PREFIX: Record<string, string> = {
  pwnedPasswordsOptions: 'pwnedpasswords',
  doors: 'throttle-doors',
  nestjsAdapterOptions: 'nestjs-authmodule',
  trpcAdapterOptions: 'trpc-createauthcontext',
  csrfHandout: 'csrf-handout',
  turnstileOptions: 'turnstile',
  argon2idOptions: 'argon2id',
  redisStoresOptions: 'redisstores',
  legacySessionsOptions: 'adoptlegacysessions',
  prismaStoresOptions: 'prismastores',
};

/** The numbers a description may hold, by row id. */
const DOES_FACTS: Record<string, readonly string[]> = {
  secret: [`at least ${minSecretBytes} bytes`],
  previoussecret: [`at least ${minSecretBytes} bytes`],
  'password-policy-minlength': [`below ${minConfigurableLength} is refused`],
  'emailverification-ttl': [`a ${TOKEN_BYTES}-byte link`],
  'emailverification-digits': [`Must be ${minDigits} to ${maxDigits}`],
  'passwordreset-kind': [`link of ${TOKEN_BYTES} random bytes`],
  'passwordreset-digits': [`Must be ${minDigits} to ${maxDigits}`],
  'emailchange-digits': [`Must be ${minDigits} to ${maxDigits}`],
  'throttle-lockout-baselock': [`multiplies it by ${lockFactor}`],
  'argon2id-timecost': [`OWASP's ${owaspTimeCost} at this memory`],
  'adoptlegacysessions-take': ['SHA-256'],
};

// The tests -------------------------------------------------------------------

const tables = Object.entries(EXPECTED).map(([name, expected]) => {
  const rows = (keys as unknown as Record<string, readonly Row[] | undefined>)[name];

  return { name, expected, rows: rows ?? [], prefix: PREFIX[name] };
});

describe('configuration reference tables', () => {
  it('lists every exported table here', () => {
    const exported = Object.entries(keys)
      .filter(([, value]) => Array.isArray(value))
      .map(([name]) => name);

    expect(exported.sort()).toEqual(Object.keys(EXPECTED).sort());
  });

  for (const { name, expected, rows, prefix } of tables) {
    it(`${name}: every default is the one the code uses`, () => {
      const shown = Object.fromEntries(
        rows.map((row) => [keys.rowId(row.key, prefix), row.default]),
      );

      expect(shown).toEqual(expected);
    });

    it(`${name}: a description holds no number that is not checked here`, () => {
      for (const row of rows) {
        const id = keys.rowId(row.key, prefix);
        const facts = DOES_FACTS[id] ?? [];
        let rest = row.does;

        expect(missingFacts(rest, facts)).toEqual([]);
        for (const fact of facts) rest = rest.replace(fact, ' ');
        // The hasher's name is not a number.
        rest = rest.replace(/\bargon2(?:id)?\b/gu, ' ');
        expect({ id, rest: /\d/u.test(rest) ? rest : '' }).toEqual({ id, rest: '' });
      }
    });
  }

  it('gives every anchored row a distinct id', () => {
    const ids = tables
      .filter(({ name }) => name !== 'essentials')
      .flatMap(({ rows, prefix }) => rows.map((row) => keys.rowId(row.key, prefix)));

    expect(ids.filter((id, i) => ids.indexOf(id) !== i)).toEqual([]);
  });
});

/** The keys `interface AuthConfig` declares, by the TypeScript parser. */
function authConfigKeys(): string[] {
  const file = ts.createSourceFile(
    'config.ts',
    source('auth/src/core/config.ts'),
    ts.ScriptTarget.Latest,
    true,
  );
  const found: string[] = [];

  file.forEachChild((node) => {
    if (ts.isInterfaceDeclaration(node) && node.name.text === 'AuthConfig')
      for (const member of node.members) found.push(member.name?.getText(file) ?? '');
  });

  return found;
}

describe('configuration reference coverage', () => {
  it('has a row for every key of AuthConfig', () => {
    const declared = authConfigKeys();
    // The tables of a group (`session.cookie.name`) are drawn under their first segment.
    const documented = new Set(
      tables
        .filter(({ prefix }) => !prefix)
        .flatMap(({ rows }) => rows.map((row) => row.key.split('.')[0])),
    );

    expect(declared).toContain('previousSecret');
    expect(declared.filter((key) => !documented.has(key))).toEqual([]);
  });
});

describe('configuration reference full example', () => {
  const config = authConfig({
    stores: {} as never,
    mailer: { send: async () => {} } as Mailer,
    secret: 'x'.repeat(minSecretBytes),
    origin: 'https://example.com',
  });

  it('writes the defaults the code uses', () => {
    const idle = config.session.idleTimeout;

    expect<unknown>(config.password.policy).toEqual({ minLength, maxLength });
    expect<unknown[]>([
      config.session.absoluteTtl,
      config.session.rememberMeTtl,
      config.session.touchInterval,
      config.session.freshAuthAge,
      config.session.maxPerUser,
    ]).toEqual([absoluteTtl, rememberMeTtl, touchInterval, freshAuthAge, maxPerUser]);
    expect<string>(idle({ rememberMe: false, attributes: undefined as never })).toBe(idleTimeout);
    expect<string>(idle({ rememberMe: true, attributes: undefined as never })).toBe(idleRemembered);
    expect<unknown>(config.session.cookie).toEqual({
      name: cookieName,
      secure: cookieSecure === 'true',
      sameSite: cookieSameSite,
    });
    expect<string>(config.email.normalize).toBe(defaultPolicy);
    expect<unknown>(config.emailVerification).toEqual({
      kind: 'code',
      ttl: verificationTtl.code,
      digits,
      maxAttempts,
    });
    expect<object>(config.passwordReset).toMatchObject({ kind: 'link', ttl: resetTtl.link });
    expect<object>(config.emailChange).toMatchObject({ kind: 'code', ttl: changeTtl.code });

    const lockoutRows: Record<string, string> = Object.fromEntries(
      keys.lockout.map((row) => [row.key, row.default]),
    );
    const { lockout, doors } = config.throttle;

    expect(rule(lockout.perAccountIp.limit, lockout.perAccountIp.window)).toBe(
      lockoutRows['throttle.lockout.perAccountIp'] ?? '',
    );
    expect(rule(lockout.perAccount.limit, lockout.perAccount.window)).toBe(
      lockoutRows['throttle.lockout.perAccount'] ?? '',
    );
    expect([lockout.baseLock, lockout.maxLock, lockout.quietPeriod].map(str)).toEqual([
      str(lockoutDefault('baseLock')),
      str(lockoutDefault('maxLock')),
      str(lockoutDefault('quietPeriod')),
    ]);
    expect<unknown>(doors.login).toEqual(DEFAULT_DOOR_LIMITS.login);
  });

  it('every value it writes equals the table row for that key', () => {
    const rows = new Map(
      tables
        .filter(({ prefix }) => !prefix)
        .flatMap(({ rows: r }) => r.map((row) => [row.key, row.default])),
    );
    const flat: [string, string | number | boolean][] = [];
    const walk = (value: unknown, path: string) => {
      if (value && typeof value === 'object' && !Array.isArray(value) && !rows.has(path)) {
        for (const [k, v] of Object.entries(value)) walk(v, path ? `${path}.${k}` : k);
      } else if (
        typeof value === 'string' ||
        typeof value === 'number' ||
        typeof value === 'boolean'
      ) {
        flat.push([path, value]);
      }
    };

    // The hasher, the breach checker and the doors are objects of their own; the
    // doors are checked against DEFAULT_DOOR_LIMITS above.
    walk(
      {
        ...config,
        secret: undefined,
        stores: undefined,
        password: { policy: config.password.policy },
        throttle: { lockout: config.throttle.lockout },
      },
      '',
    );

    for (const [path, value] of flat) {
      const shown = rows.get(path) ?? '';

      // A key the table gives per kind ("'15m' for codes, ...") shows the value among them.
      expect({
        path,
        ok: shown.includes(typeof value === 'string' ? str(value) : lit(value)),
      }).toEqual({
        path,
        ok: true,
      });
    }
  });
});

describe('configuration reference page', () => {
  const page = readFileSync(join(SITE, 'src/content/docs/reference/configuration.mdx'), 'utf8');

  it('states the startup refusals with the numbers the code uses', () => {
    expect(Number.isInteger(minRevertDays)).toBe(true);
    expect(
      missingFacts(page, [
        `\`password.policy.minLength\` is below ${minConfigurableLength}`,
        `is outside ${minDigits} to ${maxDigits}`,
        `\`emailChange.revertTtl\` is shorter than ${minRevertDays} days`,
        `\`throttle.lockout.permanent.afterLocks\` is not a whole number of at least ${minAfterLocks}`,
        `\`session.cookie.sameSite\` is a fixed \`'none'\` while \`session.cookie.secure\` is \`false\``,
        '`session.cookie.secure` is not `true` or `false`',
        '`registration.revealExisting`, `registration.autoLogin` or `passwordReset.markEmailVerified` is not `true` or `false`',
        '`emailVerification.maxAttempts`, `passwordReset.maxAttempts` or `emailChange.maxAttempts` is not a whole number of at least 1',
        '`throttle.doors` is not a whole number of at least 1, or its `window` is zero',
        '`throttle.lockout.revealLocked` or `throttle.lockout.permanent.trustedDevices` is not `true` or `false`',
      ]),
    ).toEqual([]);
  });

  it('draws every table the module exports', () => {
    for (const name of Object.keys(EXPECTED)) expect(page).toContain(`rows={${name}}`);
  });
});
