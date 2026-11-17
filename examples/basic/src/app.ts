/**
 * A small JSON API on node:http that uses every piece a real app needs:
 * Prisma for users and tokens, Redis for sessions and rate limits, Argon2id,
 * the session cookie, and CSRF protection (Origin allowlist, Sec-Fetch-Site
 * when the browser sends it, and a signed double-submit token bound to the
 * session, or before sign-in to a random per-browser pre-session id), and
 * the trusted-device cookie, set with every new session, that lets the
 * owner's correct password through an account lock.
 *
 * Routes:
 *   GET  /api/csrf          issue a CSRF token (cookie + body)
 *   POST /api/register      { email, password }
 *   POST /api/login         { email, password, rememberMe? }
 *   POST /api/verify-email  { code }                 signed in
 *   GET  /api/me                                      signed in
 *   GET  /api/sessions                                signed in
 *   POST /api/logout
 *
 * Organisations, with the membership guards (`@noctcore/auth/membership`):
 *   POST   /api/orgs                                  signed in; the caller becomes its owner
 *   POST   /api/orgs/:org/members         { userId, role }   an owner or admin of :org
 *   POST   /api/orgs/:org/members/:user   { role }           change a role; revokes :user's sessions
 *   DELETE /api/orgs/:org/members/:user                     remove; revokes :user's sessions
 */
import { randomBytes } from 'node:crypto';
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
import { membership } from '@noctcore/auth/membership';
import { PrismaMembershipStore, prismaStores } from '@noctcore/auth-prisma';
import { redisStores } from '@noctcore/auth-redis';
import type { Redis } from 'ioredis';
import type { PrismaClient } from './generated/prisma/client';

export interface AppOptions {
  readonly prisma: PrismaClient;
  readonly redis: Redis;
  readonly mailer: Mailer;
  /** The app's own origin, e.g. https://app.example. */
  readonly origin: string;
  /** At least 32 bytes: code HMACs and trusted-device tokens. */
  readonly secret: string;
  /** At least 32 bytes, and different from `secret`: signs CSRF tokens only. */
  readonly csrfSecret: string;
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
  self_target: 403,
  last_admin: 409,
  captcha_unavailable: 503,
};

/** /api/orgs/:org/members and /api/orgs/:org/members/:user */
const MEMBERS = /^\/api\/orgs\/([0-9a-f]{16})\/members(?:\/([^/]+))?$/u;

export function createApp(options: AppOptions) {
  if (options.secret === options.csrfSecret)
    throw new Error('Use separate secrets for auth and CSRF');

  const secret = new TextEncoder().encode(options.secret);
  const csrfSecret = new TextEncoder().encode(options.csrfSecret);

  const { users, tokens } = prismaStores({
    delegate: options.prisma.user,
    tokenDelegate: options.prisma.authToken,
  });

  const { sessions, counters } = redisStores(options.redis, {
    prefix: options.redisPrefix ?? 'example:',
  });

  // Who belongs to which organisation, written only through this store.
  const members = new PrismaMembershipStore({
    client: options.prisma,
    member: options.prisma.authMember,
    scope: options.prisma.authMemberScope,
  });

  const auth = createAuth({
    stores: { users, tokens, sessions, counters },
    password: { hasher: argon2id(), breachCheck: false },
    session: { cookie: { secure: options.secureCookies } },
    secret,
    urls: { resetPassword: (token) => `${options.origin}/reset-password#${token}` },
    mailer: options.mailer,
    // The last owner or admin of an organisation can be neither demoted nor removed.
    plugins: [membership({ store: members, adminRoles: ['owner', 'admin'] })],
  });

  const csrfCookieName = options.secureCookies ? '__Host-csrf' : 'csrf';
  const preSessionCookieName = options.secureCookies ? '__Host-presession' : 'presession';
  const PRE_SESSION = /^[0-9a-f]{32}$/u;

  /** A random id per logged-out browser, so a CSRF token minted in one browser fails in every other. */
  function newPreSession(): { id: string; spec: CookieSpec } {
    const id = randomBytes(16).toString('hex');

    return {
      id,
      spec: {
        name: preSessionCookieName,
        value: id,
        attributes: { httpOnly: true, secure: options.secureCookies, sameSite: 'lax', path: '/' },
      },
    };
  }

  /** Signed in: bound to the session. Signed out: bound to the browser's pre-session id. */
  function binding(
    session: StoredSession<unknown> | null,
    preSession: string | null,
  ): string | null {
    if (session) return `session:${session.id}`;

    return preSession ? `pre:${preSession}` : null;
  }

  function csrfCookie(bound: string): { spec: CookieSpec; token: string } {
    const token = createCsrfToken(csrfSecret, bound);

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
      ip:
        clientIp({
          remoteAddress: req.socket.remoteAddress,
          forwardedFor: req.headers['x-forwarded-for'],
          trustedHops: 0,
        }) ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? '',
      ...(req.headers.origin ? { origin: req.headers.origin } : {}),
    };

    const sessionToken = cookies.get(auth.cookieName) ?? null;

    const validated = sessionToken
      ? await auth.validateRequest({ token: sessionToken, meta })
      : null;

    const session = validated?.ok ? validated.value : null;
    const cookiePreSession = cookies.get(preSessionCookieName);

    const preSession =
      cookiePreSession && PRE_SESSION.test(cookiePreSession) ? cookiePreSession : null;

    // CSRF, for every unsafe method: the Origin must be ours, Sec-Fetch-Site
    // must say same-origin whenever the browser sends it, and the
    // double-submit token must match the cookie and be bound to this session
    // (or, signed out, to this browser's pre-session id).
    if (method !== 'GET' && method !== 'HEAD') {
      const secFetchSite = req.headers['sec-fetch-site'];

      const originOk = verifyRequestOrigin({
        method,
        origin: req.headers.origin,
        allowedOrigins: [options.origin],
      });

      const siteOk =
        secFetchSite === undefined ||
        verifyFetchSite({ method, secFetchSite: String(secFetchSite) });

      const bound = binding(session, preSession);

      const tokenOk =
        bound !== null &&
        verifyCsrfToken({
          cookieToken: cookies.get(csrfCookieName),
          headerToken: header(req, 'x-csrf-token'),
          binding: bound,
          secrets: [csrfSecret],
        });

      if (!originOk || !siteOk || !tokenOk) return send(res, 403, { error: { code: 'forbidden' } });
    }

    const route = `${method} ${url.pathname}`;
    const body = method === 'POST' ? await readJson(req) : {};

    switch (route) {
      case 'GET /api/csrf': {
        const fresh = session || preSession ? null : newPreSession();
        const csrf = csrfCookie(binding(session, preSession ?? fresh?.id ?? null) ?? '');

        return send(
          res,
          200,
          { csrfToken: csrf.token },
          fresh ? [fresh.spec, csrf.spec] : [csrf.spec],
        );
      }

      case 'POST /api/register': {
        const result = await auth.register({
          email: str(body['email']),
          password: str(body['password']),
          meta,
        });

        if (!result.ok) return failure(res, result);

        return send(res, 202, { status: 'check-your-email' });
      }

      case 'POST /api/login': {
        const result = await auth.login({
          email: str(body['email']),
          password: str(body['password']),
          rememberMe: body['rememberMe'] === true,
          deviceToken: auth.readDeviceToken(req.headers.cookie),
          meta,
        });

        if (!result.ok) return failure(res, result);

        if (result.value.kind === 'challenge') {
          return send(res, 200, {
            challenge: result.value.challenge,
            methods: result.value.methods,
          });
        }

        return signedIn(res, result.value.session.cookie, result.value.session.session, {}, [
          result.value.session.deviceCookie,
        ]);
      }

      case 'POST /api/verify-email': {
        if (!session)
          return failure(res, { ok: false, code: 'session_expired', reason: 'no_session' });

        const result = await auth.verifyEmailCode({ session, code: str(body['code']), meta });

        if (!result.ok) return failure(res, result);
        if (!result.value.session) return send(res, 200, { verified: true });

        return signedIn(
          res,
          result.value.session.cookie,
          result.value.session.session,
          { verified: true },
          [result.value.session.deviceCookie],
        );
      }

      case 'GET /api/me': {
        if (!session)
          return failure(res, { ok: false, code: 'session_expired', reason: 'no_session' });

        const user = await users.findById(session.userId);

        if (!user)
          return failure(res, { ok: false, code: 'session_expired', reason: 'user_missing' });

        return send(res, 200, { user });
      }

      case 'GET /api/sessions': {
        if (!session)
          return failure(res, { ok: false, code: 'session_expired', reason: 'no_session' });

        return send(res, 200, { sessions: await auth.sessions.list(session) });
      }

      case 'POST /api/logout': {
        const { cookie } = await auth.logout({ token: sessionToken, meta });
        // Signed out again: a fresh pre-session id, and a token bound to it.
        const fresh = newPreSession();
        const csrf = csrfCookie(binding(null, fresh.id) ?? '');

        return send(res, 200, { csrfToken: csrf.token }, [cookie, fresh.spec, csrf.spec]);
      }

      case 'POST /api/orgs': {
        if (!session)
          return failure(res, { ok: false, code: 'session_expired', reason: 'no_session' });

        // A server-made id: nobody can claim an organisation that already exists.
        const orgId = randomBytes(8).toString('hex');

        await members.addMember({ scope: orgId, userId: session.userId, role: 'owner' });

        return send(res, 201, { orgId });
      }

      default:
        return handleMembers(res, url, method, body, session, meta);
    }
  }

  /** The member routes. The flows refuse self-targets and the last admin, and revoke on change. */
  async function handleMembers(
    res: ServerResponse,
    url: URL,
    method: string,
    body: Record<string, unknown>,
    session: StoredSession<Record<string, never>> | null,
    meta: RequestMeta,
  ): Promise<void> {
    const match = MEMBERS.exec(url.pathname);

    if (!match) return send(res, 404, { error: { code: 'not_found' } });
    if (!session) return failure(res, { ok: false, code: 'session_expired', reason: 'no_session' });

    const scope = match[1] ?? '';
    const target = match[2];

    if (method === 'POST' && target === undefined) {
      const result = await auth.membership.add({
        session,
        scope,
        userId: str(body['userId']),
        role: str(body['role']),
        meta,
      });

      return result.ok ? send(res, 201, { member: result.value }) : failure(res, result);
    }

    if (method === 'POST' && target !== undefined) {
      const result = await auth.membership.changeRole({
        session,
        scope,
        userId: decodeURIComponent(target),
        role: str(body['role']),
        meta,
      });

      return result.ok ? send(res, 200, { member: result.value }) : failure(res, result);
    }

    if (method === 'DELETE' && target !== undefined) {
      const result = await auth.membership.remove({
        session,
        scope,
        userId: decodeURIComponent(target),
        meta,
      });

      return result.ok ? send(res, 200, { removed: true }) : failure(res, result);
    }

    return send(res, 404, { error: { code: 'not_found' } });
  }

  /** A new session means a new CSRF binding: hand out both. */
  function signedIn(
    res: ServerResponse,
    cookie: CookieSpec,
    session: StoredSession<unknown>,
    extra: object = {},
    more: CookieSpec[] = [],
  ) {
    const csrf = csrfCookie(binding(session, null) ?? '');

    return send(res, 200, { ...extra, csrfToken: csrf.token }, [cookie, csrf.spec, ...more]);
  }

  const server: Server = createServer((req, res) => {
    handle(req, res).catch((error: unknown) => {
      process.stderr.write(
        `request failed: ${error instanceof Error ? error.stack : String(error)}\n`,
      );

      if (!res.headersSent) send(res, 500, { error: { code: 'internal' } });
    });
  });

  return { server, auth };
}

function failure(res: ServerResponse, result: AuthFailure) {
  const error = toPublicError(result);

  const headers: Record<string, string> = error.retryAfterSeconds
    ? { 'retry-after': String(error.retryAfterSeconds) }
    : {};

  return send(res, STATUS[error.code] ?? 400, { error }, [], headers);
}

function send(
  res: ServerResponse,
  status: number,
  body: unknown,
  cookies: CookieSpec[] = [],
  headers: Record<string, string> = {},
) {
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
