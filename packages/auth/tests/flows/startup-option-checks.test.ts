/**
 * The startup checks finished after the boolean and limit sweep: every
 * option read without a type check before now refuses a value of the wrong
 * type when createAuth (or the factory that reads it) runs, with an
 * AuthConfigError that names the option, instead of a raw TypeError at
 * startup or a crash on the first request that reads it. A key left out,
 * undefined or null still gives its default.
 */
import { describe, expect, it } from 'vitest';
import { AuthConfigError, Throttle } from '../../src';
import { resolveCsrfSettings, type CsrfSettingsInput } from '../../src/http/csrf-adapter';
import { resolveSameSite } from '../../src/http/cookie';
import { resolveClientIpHeader } from '../../src/http/ip';
import { turnstile, type TurnstileOptions } from '../../src/http/turnstile';
import { argon2id } from '../../src/password/argon2';
import { pwnedPasswords } from '../../src/password/breach';
import { invitations, type InvitationsOptions } from '../../src/plugins/invitations';
import { membership } from '../../src/plugins/membership';
import { twoFactor } from '../../src/plugins/two-factor';
import {
  manualClock,
  MemoryCounterStore,
  MemoryInvitationStore,
  MemoryMembershipStore,
  MemoryTwoFactorStore,
} from '../../src/testing';
import { testCipher } from '../two-factor/setup';
import { SECRET, setup } from './setup';

type Overrides = Parameters<typeof setup>[0];

/** Nests `value` under a dotted path: `at('a.b', 1)` is `{ a: { b: 1 } }`. */
function at(path: string, value: unknown): Overrides {
  return path
    .split('.')
    .reduceRight<unknown>((inner, key) => ({ [key]: inner }), value) as Overrides;
}

/** Values no `Duration` parser accepts: a typo, a unit it does not know, `NaN`, a negative, a boolean. */
const NOT_DURATIONS = ['soon', '15 min', '1w', Number.NaN, -1, true] as const;

const MINUTE = 60_000;
const DAY = 24 * 60 * MINUTE;

describe('throttle.lockout', () => {
  it('boots with the defaults when lockout is null', () => {
    const { auth } = setup({ throttle: { lockout: null as never } });

    expect(auth.context.throttle.deviceMaxAgeMs).toBe(30 * DAY);
    expect(auth.context.throttle.revealLocked).toBe(false);
  });

  it('takes a null lockout like a missing one when built directly', () => {
    const clock = manualClock(0);
    const counters = new MemoryCounterStore(clock);

    expect(new Throttle(counters, clock, null).deviceMaxAgeMs).toBe(
      new Throttle(counters, clock).deviceMaxAgeMs,
    );
  });

  it('refuses a rule that is not an object', () => {
    for (const rule of ['5/15m', 5, true])
      expect(() => setup(at('throttle.lockout.perAccount', rule))).toThrow(
        'throttle.lockout.perAccount must be a { limit, window } rule',
      );
  });
});

describe('durations', () => {
  const paths = [
    'emailVerification.ttl',
    'passwordReset.ttl',
    'passwordReset.ticketTtl',
    'emailChange.ttl',
    'emailChange.revertTtl',
    'emailChange.blockAfterRevert',
    'session.freshAuthAge',
    'session.absoluteTtl',
    'session.rememberMeTtl',
    'session.touchInterval',
    'session.idleTimeout',
    'throttle.lockout.baseLock',
    'throttle.lockout.maxLock',
    'throttle.lockout.quietPeriod',
    'throttle.lockout.deviceMaxAge',
    'background.timeout',
  ];

  it.each(paths)('refuses a %s that is not a duration, naming the key', (path) => {
    for (const value of NOT_DURATIONS) {
      const boot = () => setup(at(path, value));

      expect(boot).toThrow(AuthConfigError);
      expect(boot).toThrow(`${path} must be a duration`);
    }

    expect(() => setup(at(path, null))).not.toThrow();
  });

  it.each(['perAccountIp', 'perAccount', 'perDevice'])(
    'refuses a throttle.lockout.%s.window that is not a duration, naming the key',
    (rule) => {
      const path = `throttle.lockout.${rule}`;

      for (const window of NOT_DURATIONS) {
        expect(() => setup(at(path, { limit: 5, window }))).toThrow(
          `${path}.window must be a duration`,
        );
      }

      // A rule left out, or a window left out, keeps the default.
      expect(() => setup(at(path, null))).not.toThrow();
      expect(() => setup(at(path, { limit: 5, window: null }))).not.toThrow();
    },
  );

  it('signs in with a null session.idleTimeout, which gives the default', async () => {
    const { signedInUser, sessionOf } = setup({ session: { idleTimeout: null as never } });
    const { token, session } = await signedInUser();

    expect(session.idleTimeoutMs).toBe(30 * MINUTE);
    expect(await sessionOf(token)).not.toBeNull();
  });
});

describe('kinds', () => {
  const kinds: [path: string, message: string][] = [
    ['emailVerification.kind', "emailVerification.kind must be 'code' or 'link'"],
    ['passwordReset.kind', "passwordReset.kind must be 'link' or 'code'"],
    ['emailChange.kind', "emailChange.kind must be 'code' or 'link'"],
  ];

  it.each(kinds)('refuses a %s that is neither kind', (path, message) => {
    // A typo would read as the other kind, since the flows compare with `=== 'link'`.
    for (const value of ['Link', 'CODE', 'sms', 1, true])
      expect(() => setup(at(path, value))).toThrow(message);

    expect(() => setup(at(path, 'link'))).not.toThrow();
    expect(() => setup(at(path, 'code'))).not.toThrow();
    expect(() => setup(at(path, null))).not.toThrow();
  });
});

describe('callbacks', () => {
  const link = (token: string) => `https://app.example/x#${token}`;

  const urls = {
    verifyEmail: link,
    resetPassword: link,
    confirmEmailChange: link,
    revertEmailChange: link,
  };

  it.each(Object.keys(urls))('refuses a urls.%s that is not a function', (key) => {
    for (const value of ['https://app.example/x', true, {}]) {
      expect(() => setup({ urls: { ...urls, [key]: value } })).toThrow(
        `urls.${key} must be a function`,
      );
    }
  });

  it('refuses a passwordReset.enqueue that is not a function', () => {
    expect(() => setup({ passwordReset: { enqueue: 'reset-queue' as never } })).toThrow(
      'passwordReset.enqueue must be a function',
    );

    expect(() => setup({ passwordReset: { enqueue: async () => undefined } })).not.toThrow();
  });

  it('refuses a password.breachCheck that is neither a checker nor false', () => {
    const withCheck = (breachCheck: unknown) => () =>
      setup({ password: { hasher: setup().auth.context.hasher, breachCheck } as never });

    for (const value of ['false', true, 0, {}])
      expect(withCheck(value)).toThrow('password.breachCheck must be a breach checker');

    for (const value of [false, null, undefined, async () => 'clean' as const])
      expect(withCheck(value)).not.toThrow();
  });

  it('refuses a captcha that is not a verifier', () => {
    for (const value of ['false', true, {}, () => 'pass'])
      expect(() => setup({ captcha: value as never })).toThrow(
        'captcha must be a captcha verifier',
      );

    expect(() => setup({ captcha: null as never })).not.toThrow();
    expect(() => setup({ captcha: { verify: async () => 'pass' } })).not.toThrow();
  });
});

describe('session', () => {
  it('refuses a session.attributes without a parse function', () => {
    for (const value of [{}, 'zod', { parse: true }])
      expect(() => setup({ session: { attributes: value as never } })).toThrow(
        'session.attributes must be a schema with a parse function',
      );

    expect(() => setup({ session: { attributes: null as never } })).not.toThrow();
  });

  it('refuses a session.cookie.name that is not a string', () => {
    for (const name of [42, true, ['session']])
      expect(() => setup({ session: { cookie: { name: name as never } } })).toThrow(
        'session.cookie.name must be a string',
      );

    expect(() => setup({ session: { cookie: { name: null as never } } })).not.toThrow();
  });

  it('refuses a fixed session.cookie.sameSite outside lax, strict and none', () => {
    // `'None'` used to skip the Secure check and still be written as `None`.
    for (const sameSite of ['None', 'Lax', 'off', 1]) {
      expect(() =>
        setup({ session: { cookie: { secure: false, sameSite: sameSite as never } } }),
      ).toThrow("session.cookie.sameSite must be 'lax', 'strict' or 'none'");
    }

    for (const sameSite of ['lax', 'strict', null])
      expect(() =>
        setup({ session: { cookie: { secure: false, sameSite: sameSite as never } } }),
      ).not.toThrow();
  });

  it('refuses a value outside lax, strict and none from a sameSite function when a cookie is built', () => {
    expect(() => resolveSameSite({ sameSite: () => 'None' as never }, 'app://desktop')).toThrow(
      "session.cookie.sameSite must be 'lax', 'strict' or 'none'",
    );
  });
});

describe('secrets', () => {
  it('refuses a secret that is not a string or bytes, and a null one as missing', () => {
    for (const secret of [42, true, ['x'.repeat(32)]])
      expect(() => setup({ secret: secret as never })).toThrow('secret must be a string or bytes');

    expect(() => setup({ secret: null as never })).toThrow('secret is required');
    expect(() => setup({ secret: Buffer.from(SECRET) })).not.toThrow();
  });

  it('takes a null previousSecret as none, and refuses a list with an empty slot', () => {
    const previous = 'previous-secret-that-is-at-least-32-bytes';

    expect(() => setup({ previousSecret: null as never })).not.toThrow();

    // eslint-disable-next-line no-sparse-arrays
    expect(() => setup({ previousSecret: [, previous] as never })).toThrow(
      'previousSecret must not have empty slots',
    );

    expect(() => setup({ previousSecret: [previous] })).not.toThrow();
  });
});

describe('plugins', () => {
  it('refuses a plugins that is not a list of plugins', () => {
    const cases: [unknown, string][] = [
      ['twoFactor', 'plugins must be a list'],
      // eslint-disable-next-line no-sparse-arrays
      [[, { id: 'a' }], 'plugins must not have empty slots'],
      [[42], 'plugins must hold plugins'],
      [[null], 'plugins must hold plugins'],
      [[{}], 'Every plugin needs an id'],
      [[{ id: '' }], 'Every plugin needs an id'],
      [[{ id: 'a', flows: {} }], 'Plugin a flows must be a function'],
      [[{ id: 'a', requires: 'captcha' }], 'Plugin a requires must be a list'],
    ];

    for (const [plugins, message] of cases)
      expect(() => setup({ plugins: plugins as never })).toThrow(message);

    expect(() => setup({ plugins: null as never })).not.toThrow();
    expect(() => setup({ plugins: [{ id: 'a', flows: () => ({}) }] })).not.toThrow();
  });
});

describe('background', () => {
  it('boots with a null background or null keys, and refuses a waitUntil that is not a function', () => {
    expect(() => setup({ background: null as never })).not.toThrow();

    expect(() =>
      setup({ background: { timeout: null, maxPending: null, waitUntil: null } as never }),
    ).not.toThrow();

    expect(() => setup({ background: { waitUntil: 'later' as never } })).toThrow(
      'background.waitUntil must be a function',
    );
  });
});

describe('a valid configuration', () => {
  it('still starts and signs in with every checked option set', async () => {
    const { signedInUser } = setup({
      emailVerification: { kind: 'link', ttl: '24h' },
      passwordReset: { kind: 'code', ttl: '15m', ticketTtl: '10m', enqueue: async () => undefined },
      emailChange: { kind: 'link', ttl: '1h', revertTtl: '7d', blockAfterRevert: '30d' },
      session: {
        absoluteTtl: '24h',
        rememberMeTtl: '30d',
        idleTimeout: '30m',
        touchInterval: 60,
        freshAuthAge: '10m',
        cookie: { name: 'sid', secure: true, sameSite: 'strict' },
      },
      throttle: {
        lockout: {
          perAccount: { limit: 10, window: '15m' },
          baseLock: '5m',
          maxLock: '1h',
          quietPeriod: '24h',
          deviceMaxAge: '30d',
        },
      },
      background: { timeout: '5s', maxPending: 100, waitUntil: () => undefined },
      captcha: { verify: async () => 'pass' },
      plugins: [],
    });

    const { token } = await signedInUser();

    expect(token).toBeTypeOf('string');
  });
});

describe('argon2id', () => {
  it('refuses an unsafeAllowWeakParameters that is not true or false', () => {
    for (const value of ['true', 'false', 1])
      expect(() =>
        argon2id({ memoryCost: 1024, timeCost: 1, unsafeAllowWeakParameters: value as never }),
      ).toThrow('argon2id: unsafeAllowWeakParameters must be true or false');

    expect(() =>
      argon2id({ memoryCost: 1024, timeCost: 1, unsafeAllowWeakParameters: true }),
    ).not.toThrow();
  });

  it('refuses cost parameters that are not whole numbers, even with weak parameters allowed', () => {
    for (const key of ['memoryCost', 'timeCost', 'parallelism']) {
      for (const value of [Number.NaN, 0, 1.5, '3'])
        expect(() => argon2id({ [key]: value, unsafeAllowWeakParameters: true })).toThrow(
          `argon2id: ${key} must be a whole number of at least 1`,
        );
    }
  });

  it('refuses a pepper that is not bytes, and takes null options as the defaults', () => {
    expect(() => argon2id({ secret: 'pepper' as never })).toThrow(
      'argon2id: secret must be bytes, such as a Buffer',
    );

    expect(() => argon2id({ secret: Buffer.from('pepper') })).not.toThrow();
    expect(() => argon2id({ secret: null as never })).not.toThrow();
    expect(() => argon2id(null)).not.toThrow();
  });
});

describe('turnstile', () => {
  const make = (options: Record<string, unknown>) => () =>
    turnstile({ secret: 's', ...options } as TurnstileOptions);

  it('refuses a missing or empty secret', () => {
    for (const secret of [undefined, null, '', 42])
      expect(make({ secret })).toThrow('turnstile: secret is required');

    expect(() => turnstile(undefined as never)).toThrow('turnstile: secret is required');
  });

  it('refuses a checkAction that is not true or false', () => {
    for (const checkAction of ['false', 'true', 1])
      expect(make({ checkAction })).toThrow('turnstile: checkAction must be true or false');

    expect(make({ checkAction: true })).not.toThrow();
  });

  it('refuses expectedHostnames given as one string, which would match any part of the name', () => {
    expect(make({ expectedHostnames: 'app.example.com' })).toThrow(
      'turnstile: expectedHostnames must be a list',
    );

    expect(make({ expectedHostnames: [1] })).toThrow(
      'turnstile: expectedHostnames must be a list of strings',
    );

    expect(make({ expectedHostnames: ['app.example.com'] })).not.toThrow();
  });

  it('refuses a timeout that is not a number above zero, and callbacks that are not functions', () => {
    for (const timeoutMs of [Number.NaN, 0, -1, '5000', Number.POSITIVE_INFINITY])
      expect(make({ timeoutMs })).toThrow('turnstile: timeoutMs must be a number above zero');

    expect(make({ fetch: 'https://x' })).toThrow('turnstile: fetch must be a function');
    expect(make({ onResult: true })).toThrow('turnstile: onResult must be a function');
    expect(make({ timeoutMs: 2500.5, fetch: fetch, onResult: () => undefined })).not.toThrow();
  });
});

describe('pwnedPasswords', () => {
  it('refuses options of the wrong type, and takes null as the defaults', () => {
    const cases: [Record<string, unknown>, string][] = [
      [{ timeoutMs: Number.NaN }, 'pwnedPasswords: timeoutMs must be a number above zero'],
      [{ timeoutMs: 0 }, 'pwnedPasswords: timeoutMs must be a number above zero'],
      [{ fetch: {} }, 'pwnedPasswords: fetch must be a function'],
      [{ userAgent: 1 }, 'pwnedPasswords: userAgent must be a string'],
      [{ baseUrl: new URL('https://x') }, 'pwnedPasswords: baseUrl must be a string'],
      [{ onResult: 'log' }, 'pwnedPasswords: onResult must be a function'],
    ];

    for (const [options, message] of cases)
      expect(() => pwnedPasswords(options as never)).toThrow(message);

    expect(() => pwnedPasswords(null)).not.toThrow();
    expect(() => pwnedPasswords({ timeoutMs: 1000, userAgent: 'app' })).not.toThrow();
  });
});

describe('twoFactor', () => {
  const store = new MemoryTwoFactorStore();
  const { cipher } = testCipher();

  const make = (options: Record<string, unknown>) => () =>
    twoFactor({ store, cipher, issuer: 'Acme', ...options } as Parameters<typeof twoFactor>[0]);

  it('refuses a required that is not a function', () => {
    for (const required of [true, 'true', {}])
      expect(make({ required })).toThrow('twoFactor: required must be a function');

    expect(make({ required: () => true })).not.toThrow();
  });

  it('takes a null enforcement, required or importedRecoveryCodes as left out', () => {
    expect(make({ enforcement: null, required: () => true })).not.toThrow();
    expect(make({ required: null, enforcement: () => ({ required: false }) })).not.toThrow();
    expect(make({ importedRecoveryCodes: null })).not.toThrow();
  });

  it('refuses durations that do not parse, naming the key', () => {
    const cases: [Record<string, unknown>, string][] = [
      [{ stepUpWindow: 'soon' }, 'twoFactor: stepUpWindow must be a duration'],
      [{ trustedDevices: { ttl: '30 days' } }, 'twoFactor: trustedDevices.ttl must be a duration'],
      [{ attempts: { limit: 5, window: 'soon' } }, 'twoFactor: attempts.window must be a duration'],
      [{ perIp: { limit: 5, window: Number.NaN } }, 'twoFactor: perIp.window must be a duration'],
    ];

    for (const [options, message] of cases) expect(make(options)).toThrow(message);
  });
});

describe('invitations', () => {
  const options = (overrides: Record<string, unknown>): InvitationsOptions =>
    ({
      store: new MemoryInvitationStore(),
      authorize: () => true,
      onAccept: () => undefined,
      url: (token: string) => `https://app.example/invite#${token}`,
      ...overrides,
    }) as InvitationsOptions;

  it('refuses durations that do not parse, naming the key', () => {
    expect(() => invitations(options({ ttl: 'a week' }))).toThrow(
      'invitations: ttl must be a duration',
    );

    for (const name of ['perInviter', 'perAddress', 'perIp'])
      expect(() => invitations(options({ [name]: { limit: 1, window: 'soon' } }))).toThrow(
        `invitations: ${name}.window must be a duration`,
      );
  });
});

describe('membership', () => {
  const store = new MemoryMembershipStore();

  it('refuses a canManage that is not a function', () => {
    expect(() =>
      membership({ store, adminRoles: ['admin'], canManage: 'admins' as never }),
    ).toThrow('membership: canManage must be a function');

    expect(() =>
      membership({ store, adminRoles: ['admin'], canManage: null as never }),
    ).not.toThrow();
  });

  it('refuses an adminRoles list with an empty slot, which every() skips', () => {
    // eslint-disable-next-line no-sparse-arrays
    expect(() => membership({ store, adminRoles: [, 'admin'] as never })).toThrow(
      'membership: adminRoles must list at least one role',
    );
  });
});

describe('resolveCsrfSettings', () => {
  const secret = 'csrf-secret-that-is-at-least-32-bytes-long';
  const base = { secrets: [secret], allowedOrigins: ['https://app.example'] };

  it('refuses a missing csrf object or a missing required list, naming the option', () => {
    const cases: [unknown, string][] = [
      [undefined, 'csrf is required'],
      [null, 'csrf is required'],
      [{ allowedOrigins: base.allowedOrigins }, 'csrf.secrets is required'],
      [{ ...base, secrets: null }, 'csrf.secrets is required'],
      [{ secrets: base.secrets }, 'csrf.allowedOrigins is required'],
      [
        { secrets: base.secrets, allowedOrigins: null, crossSiteOrigins: ['app://desktop'] },
        'csrf.allowedOrigins is required',
      ],
    ];

    for (const [input, message] of cases) {
      const resolve = () => resolveCsrfSettings(input as CsrfSettingsInput, false);

      expect(resolve).toThrow(AuthConfigError);
      expect(resolve).toThrow(message);
    }
  });

  it('refuses lists with an empty slot', () => {
    const cases: [unknown, string][] = [
      // eslint-disable-next-line no-sparse-arrays
      [{ ...base, secrets: [, secret] }, 'csrf.secrets must not have empty slots'],
      // eslint-disable-next-line no-sparse-arrays
      [{ ...base, secrets: [secret, ,] }, 'csrf.secrets must not have empty slots'],
      [
        // eslint-disable-next-line no-sparse-arrays
        { ...base, allowedOrigins: [, 'https://app.example'] },
        'csrf.allowedOrigins must not have empty slots',
      ],
      [
        // eslint-disable-next-line no-sparse-arrays
        { ...base, crossSiteOrigins: [, 'app://x'] },
        'csrf.crossSiteOrigins must not have empty slots',
      ],
    ];

    for (const [input, message] of cases)
      expect(() => resolveCsrfSettings(input as CsrfSettingsInput, false)).toThrow(message);
  });

  it('still takes readonly lists of strings and bytes', () => {
    const input: CsrfSettingsInput = Object.freeze({
      secrets: Object.freeze([secret, Buffer.from(secret.toUpperCase())]),
      allowedOrigins: Object.freeze(['https://app.example']),
    });

    expect(resolveCsrfSettings(input, true).secrets).toHaveLength(2);
  });
});

describe('resolveClientIpHeader', () => {
  it('takes null as left out and refuses a value that is not a string', () => {
    expect(resolveClientIpHeader(null as never, ['loopback'])).toBeUndefined();

    for (const name of [42, true, ['cf-connecting-ip']])
      expect(() => resolveClientIpHeader(name as never, ['loopback'])).toThrow(
        'clientIpHeader must be a string',
      );
  });
});
