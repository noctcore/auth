/**
 * One table of CSRF requests and the answer every adapter must give, run by
 * the core's own test and by each adapter's (auth-nestjs, auth-trpc) against
 * its real entry point. Each runner compares its adapter's answer with the
 * row, so two adapters that drift apart cannot both pass.
 *
 * No test framework is imported here: each package runs its own copy of
 * vitest, so the runners register the cases themselves.
 */
import { encodeHexLowerCase } from '@oslojs/encoding';
import { randomBytes } from '../../src/crypto/random';
import { createCsrfToken } from '../../src/http/csrf';
import { resolveCsrfSettings } from '../../src/http/csrf-adapter';

export const PARITY_ORIGIN = 'http://app.test';
export const CURRENT_SECRET = 'csrf-secret-that-is-at-least-32-bytes-long';
export const PREVIOUS_SECRET = 'previous-csrf-secret-at-least-32-bytes-long';
/** The rollover configuration every runner boots with: current first, previous after. */
export const PARITY_SECRETS = [CURRENT_SECRET, PREVIOUS_SECRET] as const;
export const DESKTOP_ORIGIN = 'app://desktop';

/** Which CSRF cookie the request carries. */
type TokenKind =
  /** Bound to this request's session or pre-session, under the current secret. */
  | 'own'
  /** Bound to this binding, signed by the previous secret (still accepted during a rollover). */
  | 'own-previous'
  /** Valid, but bound to another browser's pre-session. */
  | 'other'
  | 'garbage'
  | 'none';

/** The CSRF options a row runs under; every runner boots one adapter per config. */
export const PARITY_CONFIGS = {
  default: { secrets: PARITY_SECRETS, allowedOrigins: [PARITY_ORIGIN] },
  /** A desktop shell on its own scheme, whose requests arrive as `cross-site`. */
  desktop: {
    secrets: PARITY_SECRETS,
    allowedOrigins: [PARITY_ORIGIN],
    crossSiteOrigins: [DESKTOP_ORIGIN],
  },
  /** Sibling subdomains trusted through `Sec-Fetch-Site: same-site`. */
  sameSite: { secrets: PARITY_SECRETS, allowedOrigins: [PARITY_ORIGIN], allowSameSite: true },
} as const;

export type ParityConfig = keyof typeof PARITY_CONFIGS;

/** The adapters a row applies to. */
export type ParityAdapter = 'nestjs' | 'trpc';

export interface CsrfCase {
  readonly name: string;
  /**
   * The request method. A safe one (GET, HEAD, OPTIONS) gets the handout,
   * any other the verdict. tRPC carries mutations on POST only, so the other
   * unsafe methods are Nest rows.
   */
  readonly method: 'GET' | 'HEAD' | 'OPTIONS' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  /** Default `default`. */
  readonly config?: ParityConfig;
  /** Default both. */
  readonly adapters?: readonly ParityAdapter[];
  readonly signedIn: boolean;
  /** Signed out: whether the browser holds a pre-session id, or a value we could not have minted. */
  readonly preSession: 'valid' | 'malformed' | 'none';
  readonly cookie: TokenKind;
  /** What the CSRF header carries on a POST: the cookie's value, another valid token, or nothing. */
  readonly header?: 'same' | 'other' | 'none';
  /** The `Origin` header; null sends none. Default the allowed origin. */
  readonly origin?: string | null;
  /** The `Sec-Fetch-Site` header; null sends none. Default `same-origin`. */
  readonly secFetchSite?: string | null;
  readonly expected:
    | { readonly allowed: boolean }
    | {
        /** The CSRF cookies the response sets, in order. */
        readonly sets: readonly ('presession' | 'csrf')[];
        /** True when the handed-out token is the cookie the request sent. */
        readonly keeps: boolean;
      };
}

type Fields = Partial<Omit<CsrfCase, 'name' | 'expected'>>;

const post = (name: string, allowed: boolean, fields: Fields = {}): CsrfCase => ({
  name,
  method: 'POST',
  signedIn: true,
  preSession: 'none',
  cookie: 'own',
  header: 'same',
  ...fields,
  expected: { allowed },
});

const get = (
  name: string,
  sets: readonly ('presession' | 'csrf')[],
  fields: Fields = {},
): CsrfCase => ({
  name,
  method: 'GET',
  signedIn: true,
  preSession: 'none',
  cookie: 'own',
  ...fields,
  expected: { sets, keeps: sets.length === 0 },
});

export const CSRF_CASES: readonly CsrfCase[] = [
  post('passes a same-origin request with its own token', true),
  post('passes a request whose browser sends no Sec-Fetch-Site', true, { secFetchSite: null }),
  post('passes a token signed by the previous secret', true, { cookie: 'own-previous' }),
  post('passes a signed-out request bound to its pre-session', true, {
    signedIn: false,
    preSession: 'valid',
  }),
  post('refuses a cross-site Sec-Fetch-Site', false, { secFetchSite: 'cross-site' }),
  post('refuses same-site when allowSameSite is off', false, { secFetchSite: 'same-site' }),
  post('refuses Sec-Fetch-Site none', false, { secFetchSite: 'none' }),
  post('refuses a missing Origin', false, { origin: null }),
  post('refuses the null Origin', false, { origin: 'null' }),
  post('refuses an Origin outside the allowlist', false, { origin: 'https://evil.example' }),
  post('refuses a missing header token', false, { header: 'none' }),
  post('refuses a header token that differs from the cookie', false, { header: 'other' }),
  post('refuses a matching pair bound to another browser', false, {
    cookie: 'other',
    header: 'same',
  }),
  post('refuses a garbage token', false, { cookie: 'garbage' }),
  post('refuses a request with no CSRF cookie', false, { cookie: 'none', header: 'none' }),
  post('refuses a signed-out request with no pre-session', false, {
    signedIn: false,
    cookie: 'other',
  }),
  post('refuses a signed-out request with a malformed pre-session', false, {
    signedIn: false,
    preSession: 'malformed',
    cookie: 'other',
  }),
  post('passes a cross-site request from a crossSiteOrigins entry', true, {
    config: 'desktop',
    origin: DESKTOP_ORIGIN,
    secFetchSite: 'cross-site',
  }),
  post('refuses a cross-site request from an allowed origin not on crossSiteOrigins', false, {
    config: 'desktop',
    secFetchSite: 'cross-site',
  }),
  post('refuses a crossSiteOrigins entry without the token', false, {
    config: 'desktop',
    origin: DESKTOP_ORIGIN,
    secFetchSite: 'cross-site',
    header: 'none',
  }),
  post('passes same-site when allowSameSite is on', true, {
    config: 'sameSite',
    secFetchSite: 'same-site',
  }),
  post('still refuses cross-site when allowSameSite is on', false, {
    config: 'sameSite',
    secFetchSite: 'cross-site',
  }),
  ...(['PUT', 'PATCH', 'DELETE'] as const).flatMap((method) => [
    post(`passes a ${method} with its own token`, true, { method, adapters: ['nestjs'] }),
    post(`refuses a ${method} without the header token`, false, {
      method,
      adapters: ['nestjs'],
      header: 'none',
    }),
    post(`refuses a cross-site ${method}`, false, {
      method,
      adapters: ['nestjs'],
      secFetchSite: 'cross-site',
    }),
  ]),
  ...(['HEAD', 'OPTIONS'] as const).flatMap((method) => [
    get(`keeps a current token on ${method}`, [], { method }),
    get(`mints a pre-session and a CSRF cookie on a first ${method}`, ['presession', 'csrf'], {
      method,
      signedIn: false,
      cookie: 'none',
    }),
  ]),
  get('keeps a current token bound to the session', []),
  get('keeps a token signed by the previous secret', [], { cookie: 'own-previous' }),
  get('keeps a current token bound to the pre-session', [], {
    signedIn: false,
    preSession: 'valid',
  }),
  get('mints a CSRF cookie when there is none', ['csrf'], { cookie: 'none' }),
  get('mints a CSRF cookie over one bound to another browser', ['csrf'], { cookie: 'other' }),
  get('mints a CSRF cookie over a garbage one', ['csrf'], { cookie: 'garbage' }),
  get('mints a pre-session and a CSRF cookie on a first visit', ['presession', 'csrf'], {
    signedIn: false,
    cookie: 'none',
  }),
  get('mints a pre-session over a malformed one', ['presession', 'csrf'], {
    signedIn: false,
    preSession: 'malformed',
    cookie: 'other',
  }),
];

/** A session the runner signed in through its own adapter's auth. */
export interface ParitySession {
  readonly id: string;
  /** `name=value` for the session cookie. */
  readonly cookie: string;
}

/** The rows that apply to one adapter. */
export const casesFor = (adapter: ParityAdapter): readonly CsrfCase[] =>
  CSRF_CASES.filter((row) => row.adapters?.includes(adapter) ?? true);

export interface ParityRequest {
  readonly method: CsrfCase['method'];
  /** The config the runner's adapter must run under. */
  readonly config: ParityConfig;
  readonly headers: Readonly<Record<string, string>>;
  /** The CSRF cookie value the request carries, if any. */
  readonly cookieToken: string | undefined;
}

/** Plain HTTP, so the cookies carry no `__Host-` prefix, as in every runner. */
const settings = resolveCsrfSettings(PARITY_CONFIGS.default, false);

const encoder = new TextEncoder();
const SAFE = new Set(['GET', 'HEAD', 'OPTIONS']);

/** A pre-session id as the adapters mint them: 16 random bytes in lowercase hex. */
const freshPreSession = (): string => encodeHexLowerCase(randomBytes(16));

/** The binding the adapters sign: the session, or the pre-session when signed out. */
const sign = (secret: string, binding: string): string =>
  createCsrfToken(encoder.encode(secret), binding);

/** The headers of one row, for a runner that signed `session` in. */
export function buildRequest(row: CsrfCase, session: ParitySession): ParityRequest {
  const preId = freshPreSession();
  const binding = row.signedIn ? `session:${session.id}` : `pre:${preId}`;
  const other = sign(CURRENT_SECRET, `pre:${freshPreSession()}`);

  const cookieToken = {
    own: sign(CURRENT_SECRET, binding),
    'own-previous': sign(PREVIOUS_SECRET, binding),
    other,
    garbage: 'not-a-token',
    none: undefined,
  }[row.cookie];

  const cookies: string[] = [];

  if (row.signedIn) cookies.push(session.cookie);
  if (row.preSession === 'valid') cookies.push(`${settings.preSessionCookieName}=${preId}`);
  if (row.preSession === 'malformed') cookies.push(`${settings.preSessionCookieName}=xyz`);
  if (cookieToken !== undefined) cookies.push(`${settings.cookieName}=${cookieToken}`);

  const headers: Record<string, string> = {};

  if (cookies.length > 0) headers['cookie'] = cookies.join('; ');

  const origin = row.origin === undefined ? PARITY_ORIGIN : row.origin;
  const site = row.secFetchSite === undefined ? 'same-origin' : row.secFetchSite;

  if (origin !== null) headers['origin'] = origin;
  if (site !== null) headers['sec-fetch-site'] = site;

  const echoed = { same: cookieToken, other, none: undefined }[row.header ?? 'none'];

  if (!SAFE.has(row.method) && echoed !== undefined) headers[settings.headerName] = echoed;

  return { method: row.method, config: row.config ?? 'default', headers, cookieToken };
}

/** What a runner saw its adapter do with one request. */
export type Observed =
  | { readonly allowed: boolean }
  | {
      /** The names of the cookies the response set (a cleared session cookie left out). */
      readonly setCookies: readonly string[];
      /** The token handed out for the request. */
      readonly token: string;
    };

/** A token as the core signs them: a 32 hex character nonce, a dot, a 64 hex character HMAC. */
const TOKEN = /^[0-9a-f]{32}\.[0-9a-f]{64}$/u;

/**
 * The adapter's answer in the shape of the row's expectation, so each runner
 * checks a row with one `toEqual(expectedOutcome(row))`.
 */
export function outcome(request: ParityRequest, seen: Observed): unknown {
  if ('allowed' in seen) return { allowed: seen.allowed };

  return {
    setCookies: seen.setCookies,
    kept: seen.token === request.cookieToken,
    signed: TOKEN.test(seen.token),
  };
}

export function expectedOutcome(row: CsrfCase): unknown {
  if ('allowed' in row.expected) return { allowed: row.expected.allowed };

  const names = { presession: settings.preSessionCookieName, csrf: settings.cookieName };

  return {
    setCookies: row.expected.sets.map((kind) => names[kind]),
    kept: row.expected.keeps,
    signed: true,
  };
}
