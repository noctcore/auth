// Wall-clock timing benchmark for the doors an attacker can time (attack A004).
//
// The gated check is tests/attacks/A004-enumeration-by-timing.test.ts: it
// counts store calls and password verifies, so it cannot flake. This script
// measures the clock instead, with the real Argon2id hasher, for a person
// reading the numbers. It is not run in CI and never fails a build.
//
//   bun run bench:timing                       100 samples per arm, seed 20261117
//   bun run bench:timing --samples 400 --seed 7
//
// compare.ts does the measuring. Each arm repeats one address (the
// new-address sign-up excepted), so neither arm pays for creating counter
// keys the other reuses. The in-memory stores make a lookup far cheaper than a
// real database round trip, so a store call one arm skips would show up here
// as a gap of microseconds, not the milliseconds it costs in production:
// `bun run bench:timing:stores` times the sign-up pair on Postgres and Redis.
import { createAuth, type AuthConfig, type AuthPlugin, type Door } from '../../src';
import { argon2id } from '../../src/password/argon2';
import type { AuthUser } from '../../src/ports/stores';
import { manualClock, memoryStores, recordingMailer } from '../../src/testing';
import { compare, meta, SAMPLES, SEED, summarize } from './compare';

const PASSWORD = 'correct horse battery';
const WRONG = 'wrong passphrase, nearly';
const KNOWN = 'known@example.com';

const UNLIMITED = { limit: 1_000_000_000, window: '15m' } as const;

const DOORS: Door[] = [
  'login',
  'register',
  'password-reset-request',
  'password-reset-mail',
  'password-reset',
  'password-reset-code',
  'password-reset-code-address',
];

type Config = AuthConfig<AuthUser, Record<string, never>, readonly AuthPlugin[]>;

/** An app with the real hasher, a frozen clock (locks never lapse) and no door limits. */
function app(overrides: Partial<Config> = {}) {
  const clock = manualClock(Date.UTC(2026, 0, 1));
  const mailer = recordingMailer();

  const auth = createAuth({
    stores: memoryStores(clock),
    password: { hasher: argon2id(), breachCheck: false },
    secret: 'timing-benchmark-secret-at-least-32-bytes',
    urls: { resetPassword: (token) => `https://app.example/reset#${token}` },
    throttle: { doors: Object.fromEntries(DOORS.map((door) => [door, UNLIMITED])) },
    mailer,
    clock,
    ...overrides,
  } as Config);

  return { auth, mailer };
}

async function main() {
  console.log(`Timing benchmark: ${SAMPLES} samples per arm, seed ${SEED}, Argon2id defaults.`);

  // Login, with lockout budgets out of reach so a wrong password never locks.
  const open = app({
    throttle: {
      doors: Object.fromEntries(DOORS.map((door) => [door, UNLIMITED])),
      lockout: { perAccountIp: UNLIMITED, perAccount: UNLIMITED, perDevice: UNLIMITED },
    },
  });

  await open.auth.register({ email: KNOWN, password: PASSWORD, meta: meta() });

  // Login under the default lockout, with the known and an unknown address locked.
  const locked = app();

  await locked.auth.register({ email: KNOWN, password: PASSWORD, meta: meta() });

  for (let i = 0; i < 11; i++) {
    await locked.auth.login({ email: KNOWN, password: WRONG, meta: meta() });
    await locked.auth.login({ email: 'ghost@example.com', password: WRONG, meta: meta() });
  }

  // Sign-up and reset: reset jobs are dropped so only the request path is timed,
  // as an attacker sees it; the job runs off that path.
  const doors = app({ passwordReset: { enqueue: async () => undefined } });

  await doors.auth.register({ email: KNOWN, password: PASSWORD, meta: meta() });

  const codes = app({ passwordReset: { kind: 'code', enqueue: async () => undefined } });

  await codes.auth.register({ email: KNOWN, password: PASSWORD, meta: meta() });

  const results = [
    await compare({
      name: 'login: unknown address vs known address with a wrong password',
      arms: [
        [
          'unknown address',
          () => open.auth.login({ email: 'ghost@example.com', password: WRONG, meta: meta() }),
        ],
        [
          'known address, wrong password',
          () => open.auth.login({ email: KNOWN, password: WRONG, meta: meta() }),
        ],
      ],
    }),
    await compare({
      name: 'login: locked known address vs locked unknown address',
      arms: [
        [
          'locked known address',
          () => locked.auth.login({ email: KNOWN, password: PASSWORD, meta: meta() }),
        ],
        [
          'locked unknown address',
          () => locked.auth.login({ email: 'ghost@example.com', password: PASSWORD, meta: meta() }),
        ],
      ],
    }),
    await compare({
      name: 'login: locked account vs open account with a wrong password',
      arms: [
        [
          'locked account',
          () => locked.auth.login({ email: KNOWN, password: WRONG, meta: meta() }),
        ],
        [
          'open account, wrong password',
          () => open.auth.login({ email: KNOWN, password: WRONG, meta: meta() }),
        ],
      ],
    }),
    await compare({
      name: 'register: taken address vs new address',
      arms: [
        [
          'taken address',
          () => doors.auth.register({ email: KNOWN, password: PASSWORD, meta: meta() }),
        ],
        [
          'new address',
          (i) =>
            doors.auth.register({
              email: `new-${i}@example.com`,
              password: PASSWORD,
              meta: meta(),
            }),
        ],
      ],
    }),
    await compare({
      name: 'password reset request: known vs unknown address',
      arms: [
        ['known address', () => doors.auth.requestPasswordReset({ email: KNOWN, meta: meta() })],
        [
          'unknown address',
          () => doors.auth.requestPasswordReset({ email: 'ghost@example.com', meta: meta() }),
        ],
      ],
    }),
    await compare({
      name: 'reset code: wrong code for a known vs an unknown address',
      arms: [
        [
          'known address',
          () =>
            codes.auth.verifyPasswordResetCode({ email: KNOWN, code: '00000000', meta: meta() }),
        ],
        [
          'unknown address',
          () =>
            codes.auth.verifyPasswordResetCode({
              email: 'ghost@example.com',
              code: '00000000',
              meta: meta(),
            }),
        ],
      ],
    }),
  ];

  summarize(results);
}

await main();
