/**
 * A small JSON API on node:http that uses every piece a real app needs:
 * Prisma for users and tokens, Redis for sessions and rate limits, Argon2id,
 * the session cookie, and CSRF protection (Origin allowlist, Sec-Fetch-Site
 * when the browser sends it, and a signed double-submit token bound to the
 * session).
 *
 * Routes:
 *   GET  /api/csrf          issue a CSRF token (cookie + body)
 *   POST /api/register      { email, password }
 *   POST /api/login         { email, password, rememberMe? }
 *   POST /api/verify-email  { code }                 signed in
 *   GET  /api/me                                      signed in
 *   GET  /api/sessions                                signed in
 *   POST /api/logout
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import {
  clientIp,
  createAuth,
  createCsrfToken,
  parseCookieHeader,
  serializeCookie,
  toPublicError,
  verifyCsrfToken,
  verifyFetchSite,
  verifyRequestOrigin,
  type AuthFailure,
  type CookieSpec,
  type Mailer,
  type RequestMeta,
  type StoredSession,
} from '@noctcore/auth';
import { argon2id } from '@noctcore/auth/argon2';
import { prismaStores } from '@noctcore/auth-prisma';
import { redisStores } from '@noctcore/auth-redis';
import type { Redis } from 'ioredis';
import type { PrismaClient } from './generated/prisma/client';

export interface AppOptions {
  readonly prisma: PrismaClient;
  readonly redis: Redis;
  readonly mailer: Mailer;
  /** The app's own origin, e.g. https://app.example. */
  readonly origin: string;
  /** At least 32 bytes. */
  readonly secret: string;
  /** False only for plain-HTTP local development and tests. */
  readonly secureCookies: boolean;
  /** Key prefix in Redis, so several apps can share one. */
  readonly redisPrefix?: string;
}

const STATUS: Record<string, number> = {
  invalid_credentials: 401,
  session_expired: 401,
  rate_limited: 429,
  fresh_auth_required: 403,
  forbidden: 403,
  captcha_unavailable: 503,
};

export function createApp(options: AppOptions) {
  const secret = new TextEncoder().encode(options.secret);
  const { users, tokens } = prismaStores({ delegate: options.prisma.user, tokenDelegate: options.prisma.authToken });
  const { sessions, counters } = redisStores(options.redis, { prefix: options.redisPrefix ?? 'example:' });

  const auth = createAuth({
    stores: { users, tokens, sessions, counters },
    password: { hasher: argon2id(), breachCheck: false },
    session: { cookie: { secure: options.secureCookies } },
    secret,
    urls: { resetPassword: (token) => `${options.origin}/reset-password#${token}` },
    mailer: options.mailer,
  });
  const csrfCookieName = options.secureCookies ? '__Host-csrf' : 'csrf';

  function csrfCookie(binding: string): { spec: CookieSpec; token: string } {
    const token = createCsrfToken(secret, binding);
    return {
      token,
      spec: {
        name: csrfCookieName,
        value: token,
        // Readable by the page, which echoes it in the X-CSRF-Token header.
        attributes: { httpOnly: false, secure: options.secureCookies, sameSite: 'lax', path: '/' },
      },
    };
  }

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', options.origin);
    const method = req.method ?? 'GET';
    const cookies = parseCookieHeader(req.headers.cookie);
    const meta: RequestMeta = {
      ip: clientIp({ remoteAddress: req.socket.remoteAddress, forwardedFor: req.headers['x-forwarded-for'], trustedHops: 0 }) ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? '',
      ...(req.headers.origin ? { origin: req.headers.origin } : {}),
    };
    const sessionToken = cookies.get(auth.cookieName) ?? null;
    const validated = sessionToken ? await auth.validateRequest({ token: sessionToken, meta }) : null;
    const session = validated?.ok ? validated.value : null;

    // CSRF, for every unsafe method: the Origin must be ours, Sec-Fetch-Site
    // must say same-origin whenever the browser sends it, and the
    // double-submit token must match the cookie and be bound to this session.
    if (method !== 'GET' && method !== 'HEAD') {
      const secFetchSite = req.headers['sec-fetch-site'];
      const originOk = verifyRequestOrigin({ method, origin: req.headers.origin, allowedOrigins: [options.origin] });
      const siteOk = secFetchSite === undefined || verifyFetchSite({ method, secFetchSite: String(secFetchSite) });
      const tokenOk = verifyCsrfToken({
        cookieToken: cookies.get(csrfCookieName),
        headerToken: header(req, 'x-csrf-token'),
        binding: session?.id ?? 'anonymous',
        secrets: [secret],
      });
      if (!originOk || !siteOk || !tokenOk) return send(res, 403, { error: { code: 'forbidden' } });
    }

    const route = `${method} ${url.pathname}`;
    const body = method === 'POST' ? await readJson(req) : {};

    switch (route) {
      case 'GET /api/csrf': {
        const csrf = csrfCookie(session?.id ?? 'anonymous');
        return send(res, 200, { csrfToken: csrf.token }, [csrf.spec]);
      }
      case 'POST /api/register': {
        const result = await auth.register({ email: str(body.email), password: str(body.password), meta });
        if (!result.ok) return failure(res, result);
        return send(res, 202, { status: 'check-your-email' });
      }
      case 'POST /api/login': {
        const result = await auth.login({ email: str(body.email), password: str(body.password), rememberMe: body.rememberMe === true, meta });
        if (!result.ok) return failure(res, result);
        if (result.value.kind === 'challenge') return send(res, 200, { challenge: result.value.challenge, methods: result.value.methods });
        return signedIn(res, result.value.session.cookie, result.value.session.session);
      }
      case 'POST /api/verify-email': {
        if (!session) return failure(res, { ok: false, code: 'session_expired', reason: 'no_session' });
        const result = await auth.verifyEmailCode({ session, code: str(body.code), meta });
        if (!result.ok) return failure(res, result);
        if (!result.value.session) return send(res, 200, { verified: true });
        return signedIn(res, result.value.session.cookie, result.value.session.session, { verified: true });
      }
      case 'GET /api/me': {
        if (!session) return failure(res, { ok: false, code: 'session_expired', reason: 'no_session' });
        const user = await users.findById(session.userId);
        if (!user) return failure(res, { ok: false, code: 'session_expired', reason: 'user_missing' });
        return send(res, 200, { user });
      }
      case 'GET /api/sessions': {
        if (!session) return failure(res, { ok: false, code: 'session_expired', reason: 'no_session' });
        return send(res, 200, { sessions: await auth.sessions.list(session) });
      }
      case 'POST /api/logout': {
        const { cookie } = await auth.logout({ token: sessionToken, meta });
        const csrf = csrfCookie('anonymous');
        return send(res, 200, { csrfToken: csrf.token }, [cookie, csrf.spec]);
      }
      default:
        return send(res, 404, { error: { code: 'not_found' } });
    }
  }

  /** A new session means a new CSRF binding: hand out both. */
  function signedIn(res: ServerResponse, cookie: CookieSpec, session: StoredSession<unknown>, extra: object = {}) {
    const csrf = csrfCookie(session.id);
    return send(res, 200, { ...extra, csrfToken: csrf.token }, [cookie, csrf.spec]);
  }

  const server: Server = createServer((req, res) => {
    handle(req, res).catch((error: unknown) => {
      process.stderr.write(`request failed: ${error instanceof Error ? error.stack : String(error)}\n`);
      if (!res.headersSent) send(res, 500, { error: { code: 'internal' } });
    });
  });
  return { server, auth };
}

function failure(res: ServerResponse, result: AuthFailure) {
  const error = toPublicError(result);
  const headers: Record<string, string> = error.retryAfterSeconds ? { 'retry-after': String(error.retryAfterSeconds) } : {};
  return send(res, STATUS[error.code] ?? 400, { error }, [], headers);
}

function send(res: ServerResponse, status: number, body: unknown, cookies: CookieSpec[] = [], headers: Record<string, string> = {}) {
  res.writeHead(status, {
    'content-type': 'application/json',
    'cache-control': 'no-store',
    'referrer-policy': 'no-referrer',
    ...headers,
    ...(cookies.length ? { 'set-cookie': cookies.map(serializeCookie) } : {}),
  });
  res.end(JSON.stringify(body));
}

function header(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name];
  return Array.isArray(value) ? value[0] : value;
}

function str(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const type = (req.headers['content-type'] ?? '').split(';')[0]?.trim().toLowerCase();
  if (type !== 'application/json') return {};
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > 16_384) return {};
    chunks.push(chunk as Buffer);
  }
  try {
    const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    return parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}
