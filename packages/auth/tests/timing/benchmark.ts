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
// Each comparison runs its two arms in a shuffled order (from the seed) so
// drift and garbage collection land on both alike, drops the slowest 5
// percent of each arm, and reports the medians and Welch's t. A |t| under
// 4.5 (the threshold dudect uses) means this run could not tell the arms
// apart. Each arm repeats one address (the new-address sign-up excepted), so
// neither arm pays for creating counter keys the other reuses. The in-memory stores make a lookup far cheaper than a real database
// round trip, so a store call one arm skips would show up here as a gap of
// microseconds, not the milliseconds it costs in production.
import {
  createAuth,
  type AuthConfig,
  type AuthPlugin,
  type Door,
  type RequestMeta,
} from '../../src';
import { argon2id } from '../../src/password/argon2';
import type { AuthUser } from '../../src/ports/stores';
import { manualClock, memoryStores, recordingMailer } from '../../src/testing';

const PASSWORD = 'correct horse battery';
const WRONG = 'wrong passphrase, nearly';
const KNOWN = 'known@example.com';
const THRESHOLD = 4.5;

function arg(name: string, fallback: number): number {
  const index = process.argv.indexOf(`--${name}`);
  const value = index === -1 ? undefined : Number(process.argv[index + 1]);

  return value !== undefined && Number.isSafeInteger(value) && value > 0 ? value : fallback;
}

const SAMPLES = arg('samples', 100);
const SEED = arg('seed', 20_261_117);

/** mulberry32: a small seeded generator, so a run's order can be replayed. */
function seeded(seed: number): () => number {
  let state = seed >>> 0;

  return () => {
    state = (state + 0x6d2b79f5) >>> 0;

    let t = state;

    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);

    return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
  };
}

const random = seeded(SEED);
let ipCounter = 0;

/** A fresh client address per request, so the per-IP door limit never answers first. */
function meta(): RequestMeta {
  ipCounter += 1;

  return { ip: `10.${(ipCounter >> 16) & 255}.${(ipCounter >> 8) & 255}.${ipCounter & 255}` };
}

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

async function time(run: () => Promise<unknown>): Promise<number> {
  const start = process.hrtime.bigint();

  await run();

  return Number(process.hrtime.bigint() - start) / 1e6;
}

interface Stats {
  median: number;
  mean: number;
  variance: number;
  n: number;
}

function stats(samples: number[]): Stats {
  const kept = [...samples].sort((a, b) => a - b).slice(0, Math.ceil(samples.length * 0.95));
  const mean = kept.reduce((sum, x) => sum + x, 0) / kept.length;
  const variance = kept.reduce((sum, x) => sum + (x - mean) ** 2, 0) / Math.max(kept.length - 1, 1);

  return { median: kept[Math.floor(kept.length / 2)] ?? 0, mean, variance, n: kept.length };
}

function welch(a: Stats, b: Stats): number {
  const spread = Math.sqrt(a.variance / a.n + b.variance / b.n);

  return spread === 0 ? 0 : (a.mean - b.mean) / spread;
}

interface Comparison {
  name: string;
  arms: readonly [label: string, run: (i: number) => Promise<unknown>][];
}

async function compare({ name, arms }: Comparison): Promise<boolean> {
  const order = arms.flatMap((_, arm) => Array.from({ length: SAMPLES }, (__, i) => ({ arm, i })));

  for (let i = order.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));

    [order[i], order[j]] = [order[j] ?? { arm: 0, i: 0 }, order[i] ?? { arm: 0, i: 0 }];
  }

  // Warm up both paths (JIT, Argon2's first allocation) before measuring.
  for (const [, run] of arms) for (let i = 0; i < 5; i++) await run(-1 - i);

  const samples: number[][] = arms.map(() => []);

  for (const { arm, i } of order) {
    const [, run] = arms[arm] ?? arms[0] ?? ['', () => Promise.resolve()];

    samples[arm]?.push(await time(() => run(i)));
  }

  const [a, b] = samples.map(stats) as [Stats, Stats];
  const t = welch(a, b);
  const same = Math.abs(t) < THRESHOLD;
  const label = (index: number) => arms[index]?.[0] ?? '';

  console.log(`\n${name}`);

  console.log(
    `  ${label(0).padEnd(34)} median ${a.median.toFixed(3)} ms   mean ${a.mean.toFixed(3)} ms`,
  );

  console.log(
    `  ${label(1).padEnd(34)} median ${b.median.toFixed(3)} ms   mean ${b.mean.toFixed(3)} ms`,
  );

  console.log(
    `  Welch t = ${t.toFixed(2)}  ${same ? 'not distinguishable' : 'DISTINGUISHABLE'} at |t| < ${THRESHOLD}`,
  );

  return same;
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

  const distinguishable = results.filter((same) => !same).length;

  console.log(
    `\n${distinguishable} of ${results.length} comparisons distinguishable. Replay with --seed ${SEED} --samples ${SAMPLES}.`,
  );
}

await main();
