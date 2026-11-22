/**
 * The rows of the configuration reference (reference/configuration.mdx), one
 * array per table. Every cell is one line of inline Markdown: `code`,
 * [links](/auth/...) and **bold** are rendered, nothing else. Longer
 * explanations belong under the table on the page, not here.
 *
 * `default` is what the package uses when the key is left out. Every default
 * and every digit in these rows is checked against the package source by
 * site/scripts/reference-config.test.ts, so a changed default fails there.
 *
 * Each row gets the anchor `<prefix->key`, lowercased, with every run of
 * other characters turned into one hyphen: `session.cookie.sameSite` is
 * `#session-cookie-samesite`. Renaming a key renames its anchor.
 */
export interface ConfigRow {
  /** The key as an app writes it, or the option, door or field name. */
  readonly key: string;
  /** The type, short. Left out where the table says it once (the doors). */
  readonly type?: string;
  /** The value used when the key is left out, as inline Markdown. */
  readonly default: string;
  /** One line: what it does, or for the doors, what the limit is keyed by. */
  readonly does: string;
  /** In a summary table (`link`), where the key links to, when not its own row. */
  readonly anchor?: string;
}

/** The anchor of a row: `session.cookie.sameSite` is `session-cookie-samesite`. */
export function rowId(key: string, prefix?: string): string {
  return `${prefix ? `${prefix}-` : ''}${key}`
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, '-')
    .replace(/^-|-$/gu, '');
}

/** The keys a typical app sets; each links to its full row. */
export const essentials: readonly ConfigRow[] = [
  {
    key: 'stores',
    type: 'object',
    default: 'required',
    anchor: 'required',
    does: 'Users and tokens from `@noctcore/auth-prisma`, sessions and counters from `@noctcore/auth-redis`.',
  },
  {
    key: 'password.hasher',
    type: 'PasswordHasher',
    default: 'required',
    does: '`argon2id()` from `@noctcore/auth/argon2`.',
  },
  {
    key: 'secret',
    type: 'string | Uint8Array',
    default: 'required',
    does: 'The server secret, at least 32 bytes, kept apart from your CSRF secret.',
  },
  {
    key: 'mailer',
    type: 'Mailer',
    default: 'required',
    does: 'Enqueues each mail; flows never await it.',
  },
  {
    key: 'urls.resetPassword',
    type: '(token) => string',
    default: 'none',
    does: 'Required for link resets, which are the default.',
  },
  {
    key: 'password.breachCheck',
    type: 'BreachChecker | false',
    default: 'none',
    does: 'Pass `pwnedPasswords()` to refuse passwords from known breaches.',
  },
  {
    key: 'session.cookie.secure',
    type: 'boolean',
    default: '`true`',
    does: 'Set `false` only for plain-HTTP local development.',
  },
];

export const required: readonly ConfigRow[] = [
  {
    key: 'stores.users',
    type: 'UserStore',
    default: 'required',
    does: 'Users and their password hashes. `@noctcore/auth-prisma` ships one.',
  },
  {
    key: 'stores.tokens',
    type: 'TokenStore',
    default: 'required',
    does: 'One-time codes and links, stored only as hashes. `@noctcore/auth-prisma` ships one.',
  },
  {
    key: 'stores.sessions',
    type: 'SessionStore',
    default: 'required',
    does: 'Sessions. `@noctcore/auth-redis` ships one.',
  },
  {
    key: 'stores.counters',
    type: 'CounterStore',
    default: 'required',
    does: 'Rate limits and lockout. `@noctcore/auth-redis` ships one.',
  },
  {
    key: 'password.hasher',
    type: 'PasswordHasher',
    default: 'required',
    does: 'Use `argon2id()` from `@noctcore/auth/argon2`.',
  },
  {
    key: 'secret',
    type: 'string | Uint8Array',
    default: 'required',
    does: 'The server secret, at least 32 bytes. See [what rotating it does](#what-rotating-the-secret-does).',
  },
  {
    key: 'mailer',
    type: 'Mailer',
    default: 'required',
    does: '`send(event)` enqueues the mail. See [Mail into your templates and queue](/auth/build/mail/).',
  },
];

export const rotation: readonly ConfigRow[] = [
  {
    key: 'previousSecret',
    type: 'string | Uint8Array | a list of them',
    default: 'none',
    does: 'The secret, or secrets newest first, that a rotation replaced, kept for a grace window. Each at least 32 bytes, and different from `secret` and from each other. An empty string is refused, not read as unset.',
  },
];

export const password: readonly ConfigRow[] = [
  {
    key: 'password.policy.minLength',
    type: 'number',
    default: '`12`',
    does: 'The shortest password accepted. A configured minimum below 8 is refused.',
  },
  {
    key: 'password.policy.maxLength',
    type: 'number',
    default: '`256`',
    does: 'Bounds the hashing work one request can make the server do.',
  },
  {
    key: 'password.breachCheck',
    type: 'BreachChecker | false',
    default: 'none',
    does: 'Pass `pwnedPasswords()` to refuse passwords from known breaches (recommended). Fails open.',
  },
];

export const pwnedPasswordsOptions: readonly ConfigRow[] = [
  {
    key: 'timeoutMs',
    type: 'number',
    default: '`3000`',
    does: 'How long to wait for the range API, in milliseconds.',
  },
  { key: 'fetch', type: 'typeof fetch', default: 'global `fetch`', does: 'The fetch to call it with.' },
  {
    key: 'userAgent',
    type: 'string',
    default: "`'noctcore-auth'`",
    does: 'The `User-Agent` header sent.',
  },
  {
    key: 'baseUrl',
    type: 'string',
    default: "`'https://api.pwnedpasswords.com/range/'`",
    does: 'The public range API.',
  },
  {
    key: 'onResult',
    type: '(outcome) => void',
    default: 'none',
    does: 'Called with every outcome, to log or count it. Not awaited.',
  },
  { key: 'logger', type: 'Logger', default: 'silent', does: 'Where a throw from `onResult` is reported.' },
];

export const session: readonly ConfigRow[] = [
  {
    key: 'session.absoluteTtl',
    type: 'Duration',
    default: "`'24h'`",
    does: 'A session without "remember me" ends this long after sign-in, however active it is.',
  },
  {
    key: 'session.rememberMeTtl',
    type: 'Duration',
    default: "`'30d'`",
    does: "The absolute lifetime with \"remember me\". At most the session store's `maxSessionTtlMs`.",
  },
  {
    key: 'session.idleTimeout',
    type: 'Duration | (context) => Duration',
    default: "`'30m'`, or `'7d'` with \"remember me\"",
    does: 'Ends sessions left open on a shared machine.',
  },
  {
    key: 'session.touchInterval',
    type: 'Duration',
    default: "`'60s'`",
    does: 'Last-active is written at most this often, and only for a request that counts as activity (see the adapters\' `touch` option). Must be shorter than the idle timeout: a fixed one is checked at startup, the value of an `idleTimeout` function at each sign-in.',
  },
  {
    key: 'session.maxPerUser',
    type: 'number | null',
    default: '`10`',
    does: 'The oldest sessions beyond the cap are evicted when a new one is issued. `null` for no cap.',
  },
  {
    key: 'session.attributes',
    type: 'AttributeSchema',
    default: 'none',
    does: 'A schema with a zod-style `parse`, run on every read. Required when you declare session attributes.',
  },
  {
    key: 'session.freshAuthAge',
    type: 'Duration',
    default: "`'10m'`",
    does: 'How recent a credential proof must be to revoke another session or every other session.',
  },
];

export const sessionCookie: readonly ConfigRow[] = [
  {
    key: 'session.cookie.name',
    type: 'string',
    default: "`'session'`",
    does: 'Base name; `__Host-session` when Secure. Letters, digits, `_` and `-` only.',
  },
  {
    key: 'session.cookie.secure',
    type: 'boolean',
    default: '`true`',
    does: 'Turn it off only for plain-HTTP local development. Off also drops the `__Host-` prefix.',
  },
  {
    key: 'session.cookie.sameSite',
    type: "'lax' | 'strict' | 'none' | (origin) => SameSite",
    default: "`'lax'`",
    does: 'Keeps the cookie off cross-site subrequests and form posts while links into the site still work.',
  },
];

export const email: readonly ConfigRow[] = [
  {
    key: 'email.normalize',
    type: "'standard' | 'ascii' | 'unicode' | (email) => string | null",
    default: "`'standard'`",
    does: 'How every address is normalised before it is compared, stored or used as a counter key. An unknown name is refused at startup.',
  },
];

export const registration: readonly ConfigRow[] = [
  {
    key: 'registration.revealExisting',
    type: 'boolean',
    default: '`false`',
    does: 'A taken address gets the same answer as a new one, and its owner an `account-exists` mail. `true` answers `email_in_use`.',
  },
  {
    key: 'registration.autoLogin',
    type: 'boolean',
    default: '`false`',
    does: 'Issue a session on registration. Allowed only with `revealExisting`.',
  },
];

export const emailVerification: readonly ConfigRow[] = [
  {
    key: 'emailVerification.kind',
    type: "'code' | 'link'",
    default: "`'code'`",
    does: "A code typed by the signed-in user ties the proof to that account's session. `'link'` needs `urls.verifyEmail`.",
  },
  {
    key: 'emailVerification.ttl',
    type: 'Duration',
    default: "`'15m'` for codes, `'24h'` for links",
    does: 'A short code is guessable over time, so it lives briefly; a 32-byte link is not, so it can wait in an inbox.',
  },
  {
    key: 'emailVerification.digits',
    type: 'number',
    default: '`8`',
    does: "The auth guide's length. Must be 6 to 9.",
  },
  {
    key: 'emailVerification.maxAttempts',
    type: 'number',
    default: '`5`',
    does: 'Wrong guesses per code, counted atomically before each comparison.',
  },
  {
    key: 'emailVerification.linkWithoutSession',
    type: 'boolean',
    default: '`false`',
    does: 'Link verification only. Also accepts a valid link opened with no session, and signs nobody in.',
  },
];

export const passwordReset: readonly ConfigRow[] = [
  {
    key: 'passwordReset.kind',
    type: "'link' | 'code'",
    default: "`'link'`",
    does: "A single-use link of 32 random bytes. `'code'` mails digits exchanged for a short ticket. Links need `urls.resetPassword`.",
  },
  {
    key: 'passwordReset.ttl',
    type: 'Duration',
    default: "`'1h'` for links, `'15m'` for codes",
    does: 'Long enough to reach the inbox, short enough that an old mail is useless.',
  },
  { key: 'passwordReset.digits', type: 'number', default: '`8`', does: 'Must be 6 to 9.' },
  { key: 'passwordReset.maxAttempts', type: 'number', default: '`5`', does: 'Wrong guesses per code.' },
  {
    key: 'passwordReset.ticketTtl',
    type: 'Duration',
    default: "`'10m'`",
    does: 'How long the ticket a verified code becomes can set the password.',
  },
  {
    key: 'passwordReset.enqueue',
    type: '(job) => Promise<void>',
    default: 'none',
    does: 'Puts the request on your queue; your worker calls `auth.jobs.processPasswordReset(job)`.',
  },
  {
    key: 'passwordReset.markEmailVerified',
    type: 'boolean',
    default: '`true`',
    does: 'A completed reset proves the mailbox, so it marks the address verified.',
  },
];

export const emailChange: readonly ConfigRow[] = [
  {
    key: 'emailChange.kind',
    type: "'code' | 'link'",
    default: "`'code'`",
    does: "A code typed in the signed-in session of the same account. `'link'` needs `urls.confirmEmailChange` and works only in such a session.",
  },
  {
    key: 'emailChange.ttl',
    type: 'Duration',
    default: "`'15m'` for codes, `'1h'` for links",
    does: 'How long the code or link works.',
  },
  { key: 'emailChange.digits', type: 'number', default: '`8`', does: 'Must be 6 to 9.' },
  {
    key: 'emailChange.maxAttempts',
    type: 'number',
    default: '`5`',
    does: 'Wrong guesses per code, counted atomically before each comparison.',
  },
  {
    key: 'emailChange.revertTtl',
    type: 'Duration',
    default: "`'7d'`",
    does: 'How long the revert link mailed to the old address works. Shorter is refused: the owner may be away for a week.',
  },
  {
    key: 'emailChange.blockAfterRevert',
    type: 'Duration',
    default: "`'30d'`",
    does: 'After a revert, how long the account may not change to the address it lost.',
  },
];

export const urls: readonly ConfigRow[] = [
  {
    key: 'urls.verifyEmail',
    type: '(token) => string',
    default: 'none',
    does: 'Required for link verification.',
  },
  {
    key: 'urls.resetPassword',
    type: '(token) => string',
    default: 'none',
    does: 'Required for link resets, which are the default, so most apps set it.',
  },
  {
    key: 'urls.confirmEmailChange',
    type: '(token) => string',
    default: 'none',
    does: 'Required for link email changes.',
  },
  {
    key: 'urls.revertEmailChange',
    type: '(token) => string',
    default: 'none',
    does: 'The revert link of an email change; the email change flows throw without it.',
  },
];

export const lockout: readonly ConfigRow[] = [
  {
    key: 'throttle.lockout.perAccountIp',
    type: 'RateLimitRule',
    default: "5 per `'15m'`",
    does: 'Stops one source guessing at one account without touching the owner on another network.',
  },
  {
    key: 'throttle.lockout.perAccount',
    type: 'RateLimitRule',
    default: "10 per `'15m'`",
    does: 'Against guessing spread over many sources: close to one attempt a minute. Spending it locks the account.',
  },
  {
    key: 'throttle.lockout.baseLock',
    type: 'Duration',
    default: "`'5m'`",
    does: 'The first lock. Each further lock multiplies it by 3.',
  },
  {
    key: 'throttle.lockout.maxLock',
    type: 'Duration',
    default: "`'1h'`",
    does: 'Cap on a single temporary lock.',
  },
  {
    key: 'throttle.lockout.quietPeriod',
    type: 'Duration',
    default: "`'24h'`",
    does: 'The backoff resets only after this long without a new lock.',
  },
  {
    key: 'throttle.lockout.perDevice',
    type: 'RateLimitRule',
    default: "5 per `'15m'`",
    does: "Under a lock, the attempts a trusted device gets, and the budget all of an account's devices share.",
  },
  {
    key: 'throttle.lockout.deviceMaxAge',
    type: 'Duration',
    default: "`'30d'`",
    does: "The oldest trusted-device cookie accepted, checked on use. At least a minute (the clock skew a device cookie is allowed) shorter than the session store's `epochTtlMs`.",
  },
  {
    key: 'throttle.lockout.permanent',
    type: '{ afterLocks, trustedDevices? }',
    default: 'off',
    does: 'Opt in to a lock that holds until an admin clears it. See [The permanent tier](#the-permanent-tier).',
  },
  {
    key: 'throttle.lockout.permanent.trustedDevices',
    type: 'boolean',
    default: '`true`',
    does: "Whether the owner's trusted-device cookies still sign in through a permanent lock.",
  },
  {
    key: 'throttle.lockout.revealLocked',
    type: 'boolean',
    default: '`false`',
    does: 'Answer `account_locked` from login, with `retryAfterSeconds` for a temporary lock, instead of `invalid_credentials`.',
  },
];

/** `throttle.doors`: the key is the door, `does` is what the limit is keyed by. */
export const doors: readonly ConfigRow[] = [
  { key: 'login', default: "10 per `'1m'`", does: 'IP' },
  { key: 'register', default: "10 per `'1m'`", does: 'IP' },
  { key: 'password-reset-request', default: "10 per `'1m'`", does: 'IP' },
  {
    key: 'password-reset-mail',
    default: "3 per `'1h'`",
    does: 'User: reset mails one account can receive. Spent before the mail is handed over.',
  },
  { key: 'password-reset', default: "10 per `'1m'`", does: 'IP' },
  { key: 'password-reset-code', default: "10 per `'1m'`", does: 'IP' },
  {
    key: 'password-reset-code-address',
    default: "5 per `'15m'`",
    does: 'Address: code guesses for one email from every IP.',
  },
  { key: 'email-verification', default: "10 per `'1m'`", does: 'IP' },
  {
    key: 'email-verification-request',
    default: "3 per `'1h'`",
    does: 'User: verification mails one account can request. Spent before the mail is handed over.',
  },
  {
    key: 'password-change',
    default: "5 per `'5m'`",
    does: "User. Each attempt also spends login's lockout budgets (`throttle.lockout`).",
  },
  {
    key: 'reauthenticate',
    default: "5 per `'5m'`",
    does: "User. Each attempt also spends login's lockout budgets (`throttle.lockout`).",
  },
  {
    key: 'email-change-request',
    default: "3 per `'1h'`",
    does: 'User: email change requests one account can make. Spent before the mail is handed over.',
  },
  {
    key: 'email-change-address',
    default: "3 per `'1h'`",
    does: 'Address: email change requests naming one new address, from every account.',
  },
  { key: 'email-change', default: "10 per `'1m'`", does: 'IP: confirming an email change.' },
  { key: 'email-change-revert', default: "10 per `'1m'`", does: 'IP: using a revert link.' },
];

export const collaborators: readonly ConfigRow[] = [
  {
    key: 'captcha',
    type: 'CaptchaVerifier',
    default: 'none',
    does: 'Checked on login, register and the reset request. Fails closed with `captcha_unavailable`.',
  },
  {
    key: 'audit',
    type: 'AuditSink',
    default: 'none',
    does: 'Every flow emits an event for each success and each refusal, with the internal `reason`.',
  },
  {
    key: 'hooks',
    type: 'AuthHooks',
    default: 'none',
    does: 'Functions the flows call at fixed points. A hook can refuse with `refuse(code, reason)`.',
  },
  {
    key: 'plugins',
    type: 'AuthPlugin[]',
    default: '`[]`',
    does: "Plugins add hooks and flows, never endpoints. A plugin's flows appear on the auth object under its `id`.",
  },
  {
    key: 'logger',
    type: 'Logger',
    default: 'silent',
    does: 'Where the package reports what it cannot return. Messages never carry secrets.',
  },
  {
    key: 'metrics',
    type: 'Metrics',
    default: 'no-op',
    does: 'Counters such as breach check outages and door refusals. Labels never carry user input.',
  },
  {
    key: 'background.waitUntil',
    type: '(promise) => void',
    default: 'none',
    does: "Handed every background task's promise as it starts, so a runtime that freezes after the response keeps it alive.",
  },
  {
    key: 'background.timeout',
    type: 'Duration',
    default: 'none',
    does: 'Stop waiting on a task after this long; logged and counted as `timed_out`. The task is not cancelled.',
  },
  {
    key: 'background.maxPending',
    type: 'number',
    default: 'none',
    does: 'While this many tasks are still running, new ones are dropped, logged and counted as `dropped`.',
  },
  {
    key: 'clock',
    type: 'Clock',
    default: 'system clock',
    does: 'Injectable so tests move time instead of sleeping.',
  },
  {
    key: 'random',
    type: 'RandomSource',
    default: '`crypto.getRandomValues`',
    does: 'Injectable for tests.',
  },
];

export const turnstileOptions: readonly ConfigRow[] = [
  { key: 'secret', type: 'string', default: 'required', does: "Your Turnstile site's secret key." },
  {
    key: 'expectedHostnames',
    type: 'string[]',
    default: 'none',
    does: 'Hostnames the widget may be served from. Strongly recommended.',
  },
  {
    key: 'checkAction',
    type: 'boolean',
    default: 'off',
    does: "Require the widget's `action` to equal the door name (`login`, `register`, ...).",
  },
  {
    key: 'timeoutMs',
    type: 'number',
    default: '`5000`',
    does: 'How long to wait for the provider, in milliseconds.',
  },
  { key: 'fetch', type: 'typeof fetch', default: 'global `fetch`', does: 'The fetch to call it with.' },
  {
    key: 'onResult',
    type: '(outcome) => void',
    default: 'none',
    does: 'Called with every outcome, to log or count it. Not awaited.',
  },
  { key: 'logger', type: 'Logger', default: 'silent', does: 'Where a throw from `onResult` is reported.' },
];

export const argon2idOptions: readonly ConfigRow[] = [
  {
    key: 'memoryCost',
    type: 'number (KiB)',
    default: '`19456` (19 MiB)',
    does: "OWASP's memory floor. Raise it per machine; login rehashes old hashes, so raising it later costs nothing.",
  },
  {
    key: 'timeCost',
    type: 'number',
    default: '`3`',
    does: "The auth guide's pass count, stricter than OWASP's 2 at this memory.",
  },
  { key: 'parallelism', type: 'number', default: '`1`', does: "OWASP's recommendation." },
  {
    key: 'secret',
    type: 'string | Uint8Array',
    default: 'none',
    does: 'An optional pepper kept outside the database. Changing or losing it makes every hash unverifiable.',
  },
  {
    key: 'unsafeAllowWeakParameters',
    type: 'boolean',
    default: '`false`',
    does: "Parameters below every row of OWASP's equivalence table are refused unless this is set. Tests only.",
  },
];

export const redisStoresOptions: readonly ConfigRow[] = [
  {
    key: 'prefix',
    type: 'string',
    default: "`'auth:'`",
    does: 'Key prefix, so several apps can share one Redis.',
  },
  {
    key: 'maxSessionTtl',
    type: 'Duration',
    default: "`'30d'`",
    does: 'The longest session the store holds. At least your `session.rememberMeTtl`; `createAuth` refuses a longer session.',
  },
  {
    key: 'epochTtl',
    type: 'Duration',
    default: "`'90d'`",
    does: "How long a user's revocation epoch outlives its last write. Must be longer than `maxSessionTtl`, and at least a minute (the clock skew a device cookie is allowed) longer than `throttle.lockout.deviceMaxAge` and a two-factor `trustedDevices.ttl`.",
  },
  { key: 'clock', type: 'Clock', default: 'system clock', does: 'For tests.' },
];

export const legacySessionsOptions: readonly ConfigRow[] = [
  {
    key: 'take',
    type: '(id) => Promise<LegacySession | null>',
    default: 'required',
    does: 'Removes and returns, in one atomic step, the old session stored under `id` (the SHA-256 hex of the cookie token).',
  },
  {
    key: 'maxTtl',
    type: 'Duration',
    default: 'required',
    does: 'The longest an adopted session lives, from its `createdAt`. Set it to `session.rememberMeTtl`.',
  },
  { key: 'clock', type: 'Clock', default: 'system clock', does: 'For tests.' },
  {
    key: 'logger',
    type: 'Logger',
    default: 'none',
    does: 'Told about a malformed old session it dropped, with the user id only.',
  },
];

export const prismaStoresOptions: readonly ConfigRow[] = [
  {
    key: 'delegate',
    type: 'PrismaUserDelegate',
    default: 'required',
    does: '`prisma.user`, or whichever model holds your accounts.',
  },
  { key: 'tokenDelegate', type: 'PrismaAuthTokenDelegate', default: 'required', does: '`prisma.authToken`.' },
  {
    key: 'fields',
    type: 'UserFields',
    default: '`id`, `email`, `emailVerified`, `passwordHash`, `deletedAt`',
    does: 'Column names on your user model. `deletedAt: null` turns soft deletion off.',
  },
  {
    key: 'select',
    type: 'Record<string, true>',
    default: 'none',
    does: 'Extra columns to read for your own user type.',
  },
  {
    key: 'toUser',
    type: '(row) => U',
    default: 'the four auth fields',
    does: 'Maps a row to your user type.',
  },
  {
    key: 'createData',
    type: '(input) => object',
    default: 'none',
    does: 'Values for your other required columns on sign-up, such as a tenant or a display name.',
  },
];

export const nestjsAdapterOptions: readonly ConfigRow[] = [
  {
    key: 'touch',
    type: 'boolean | (request: TouchRequest) => boolean',
    default: '`true`',
    does: 'Whether a request counts as activity for the idle timeout. A predicate sees `{ method, path, headers }` and returns false for a poll. `false` touches on no request.',
  },
];

export const trpcAdapterOptions: readonly ConfigRow[] = [
  {
    key: 'touch',
    type: 'boolean | (path: string) => boolean',
    default: '`true`',
    does: 'Whether a call counts as activity for the idle timeout. A predicate gets each procedure path of the request. `false` touches on no request.',
  },
  {
    key: 'meta.touch',
    type: 'false',
    default: 'none',
    does: 'On a procedure, `.meta({ touch: false })` marks it passive. A batch touches when any of its procedures is active.',
  },
];

export const csrfHandout: readonly ConfigRow[] = [
  {
    key: 'SessionCookies.csrfToken(request, response)',
    type: '{ csrfToken: string }',
    default: 'none',
    does: 'On NestJS, returns the CSRF token of the request for a client that cannot read the cookie, from a `@Public()` GET route, and marks the response `no-store`.',
  },
  {
    key: 'ctx.auth.csrfToken()',
    type: '{ csrfToken: string }',
    default: 'none',
    does: 'On tRPC, the same from a public query sent with GET. It throws on an unsafe method, a streamed batch and a subscription.',
  },
  {
    key: 'authResponseMeta(responseMeta?)',
    type: '(opts) => ResponseMeta',
    default: 'none',
    does: 'Wraps your tRPC `responseMeta` so its cache headers cannot replace the `no-store` on a response that handed out a token. Pass it to the tRPC handler.',
  },
];
