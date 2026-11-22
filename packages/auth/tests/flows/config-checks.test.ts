/**
 * Option values that arrive from the environment as strings ("false") or as
 * `Number(undefined)` (NaN) are refused when createAuth starts: read by
 * truthiness or compared with `>`, each would quietly turn a check off.
 */
import { describe, expect, it } from 'vitest';
import { AuthConfigError } from '../../src';
import { plainHasher } from '../../src/testing';
import { setup } from './setup';

const NOT_BOOLEANS = ['false', 'true', 0, 1] as const;
const NOT_COUNTS = [Number.NaN, 0, -1, 1.5, Number.POSITIVE_INFINITY, '5'] as const;

type Overrides = Parameters<typeof setup>[0];

/** Nests `value` under a dotted path: `at('a.b', 1)` is `{ a: { b: 1 } }`. */
function at(path: string, value: unknown): Overrides {
  return path
    .split('.')
    .reduceRight<unknown>((inner, key) => ({ [key]: inner }), value) as Overrides;
}

describe('boolean options', () => {
  const options: [path: string, valid: Overrides][] = [
    ['registration.revealExisting', { registration: { revealExisting: true } }],
    ['registration.autoLogin', { registration: { revealExisting: true, autoLogin: true } }],
    ['passwordReset.markEmailVerified', { passwordReset: { markEmailVerified: false } }],
    ['session.cookie.secure', { session: { cookie: { secure: false } } }],
    ['throttle.lockout.revealLocked', { throttle: { lockout: { revealLocked: true } } }],
  ];

  it.each(options)('refuses %s unless it is true or false', (path, valid) => {
    for (const value of NOT_BOOLEANS) {
      expect(() => setup(at(path, value))).toThrow(AuthConfigError);
      expect(() => setup(at(path, value))).toThrow(`${path} must be true or false`);
    }

    expect(() => setup(valid)).not.toThrow();
    expect(() => setup(at(path, null))).not.toThrow();
  });

  it('refuses throttle.lockout.permanent.trustedDevices unless it is true or false', () => {
    const lockout = (trustedDevices: unknown) => () =>
      setup({
        throttle: { lockout: { permanent: { afterLocks: 1, trustedDevices } as never } },
      });

    for (const value of NOT_BOOLEANS) {
      expect(lockout(value)).toThrow(
        'throttle.lockout.permanent.trustedDevices must be true or false',
      );
    }

    expect(lockout(false)).not.toThrow();
    expect(lockout(undefined)).not.toThrow();
  });

  it('refuses the string "false" for revealExisting, so sign-up never answers email_in_use by mistake', () => {
    expect(() => setup({ registration: { revealExisting: 'false' as never } })).toThrow(
      'registration.revealExisting must be true or false',
    );
  });
});

describe('maxAttempts', () => {
  for (const path of [
    'emailVerification.maxAttempts',
    'passwordReset.maxAttempts',
    'emailChange.maxAttempts',
  ]) {
    it(`refuses a ${path} that is not a whole number of at least 1`, () => {
      for (const value of NOT_COUNTS) {
        expect(() => setup(at(path, value))).toThrow(
          `${path} must be a whole number of at least 1`,
        );
      }

      expect(() => setup(at(path, 1))).not.toThrow();
      expect(() => setup(at(path, null))).not.toThrow();
    });
  }
});

describe('lockout rules', () => {
  for (const rule of ['perAccountIp', 'perAccount', 'perDevice']) {
    const path = `throttle.lockout.${rule}`;

    it(`refuses a ${path}.limit that is not a whole number of at least 1`, () => {
      for (const limit of NOT_COUNTS) {
        expect(() => setup(at(path, { limit, window: '15m' }))).toThrow(
          `${path}.limit must be a whole number of at least 1`,
        );
      }

      expect(() => setup(at(path, { limit: 1, window: '15m' }))).not.toThrow();
    });

    it(`refuses a zero ${path}.window`, () => {
      expect(() => setup(at(path, { limit: 5, window: 0 }))).toThrow(
        `${path}.window must be longer than zero`,
      );
    });
  }

  for (const key of ['baseLock', 'maxLock']) {
    it(`refuses a zero throttle.lockout.${key}`, () => {
      expect(() => setup(at(`throttle.lockout.${key}`, 0))).toThrow(
        `throttle.lockout.${key} must be longer than zero`,
      );

      expect(() => setup(at(`throttle.lockout.${key}`, '1m'))).not.toThrow();
    });
  }
});

describe('door rules', () => {
  it('refuses a door limit that is not a whole number of at least 1, or a missing one', () => {
    for (const limit of [...NOT_COUNTS, undefined]) {
      expect(() =>
        setup({ throttle: { doors: { login: { limit, window: '1m' } as never } } }),
      ).toThrow('throttle.doors.login.limit must be a whole number of at least 1');
    }
  });

  it('refuses a zero door window', () => {
    expect(() => setup({ throttle: { doors: { register: { limit: 3, window: 0 } } } })).toThrow(
      'throttle.doors.register.window must be longer than zero',
    );
  });

  it('accepts a whole-number door rule', () => {
    expect(() =>
      setup({ throttle: { doors: { login: { limit: 1, window: '1s' } } } }),
    ).not.toThrow();
  });
});

describe('password policy lengths', () => {
  const withPolicy = (policy: Record<string, unknown>) => () =>
    setup({ password: { hasher: plainHasher(), breachCheck: false, policy } as never });

  it('refuses a minLength below 8 or not a whole number', () => {
    for (const minLength of [Number.NaN, 8.5, Number.POSITIVE_INFINITY, '12']) {
      expect(withPolicy({ minLength })).toThrow('password.policy.minLength must be a whole number');
    }

    expect(withPolicy({ minLength: 7 })).toThrow('password.policy.minLength must be at least 8');
  });

  it('refuses a maxLength that is not a whole number or is below minLength', () => {
    for (const maxLength of [Number.NaN, 300.5, Number.POSITIVE_INFINITY, 11]) {
      expect(withPolicy({ maxLength })).toThrow(
        'password.policy.maxLength must be a whole number of at least password.policy.minLength',
      );
    }

    expect(withPolicy({ minLength: 8, maxLength: 8 })).not.toThrow();
  });
});
