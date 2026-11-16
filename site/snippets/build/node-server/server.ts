import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import {
  clientIp,
  parseCookieHeader,
  type CookieSpec,
  type RequestMeta,
  type StoredSession,
} from '@noctcore/auth';
import { buildAuth, stores } from './auth';
import { config } from './config';
import { csrfAllowed, issueCsrfToken, newPreSession, readPreSession } from './csrf';
import { failure, header, readJson, send, str } from './http';

// Printing mail is for development; the mail guide replaces this with a queue.
const auth = buildAuth({
  async send(event) {
    process.stdout.write(`[mail] ${event.type} to ${event.to}\n`);
  },
});

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const method = req.method ?? 'GET';
  const route = `${method} ${new URL(req.url ?? '/', config.origin).pathname}`;
  const cookies = parseCookieHeader(req.headers.cookie);

  const meta: RequestMeta = {
    ip:
      clientIp({
        remoteAddress: req.socket.remoteAddress,
        forwardedFor: req.headers['x-forwarded-for'],
        trustedHops: config.trustedHops,
      }) ?? 'unknown',
    userAgent: req.headers['user-agent'],
    origin: req.headers.origin,
  };

  // One validation per request; it also slides the idle timeout.
  const token = cookies.get(auth.cookieName) ?? null;
  const validated = token ? await auth.validateRequest({ token, meta }) : null;
  const session = validated?.ok ? validated.value : null;

  const csrfOk = csrfAllowed({
    method,
    origin: req.headers.origin,
    secFetchSite: header(req, 'sec-fetch-site'),
    headerToken: header(req, 'x-csrf-token'),
    cookies,
    session,
  });

  if (!csrfOk) return send(res, 403, { error: { code: 'forbidden' } });

  const body = method === 'POST' ? await readJson(req) : {};

  switch (route) {
    case 'GET /api/csrf': {
      const preSession = readPreSession(cookies);
      const fresh = session || preSession ? null : newPreSession();
      const csrf = issueCsrfToken(session, preSession ?? fresh?.id ?? null);

      return send(
        res,
        200,
        { csrfToken: csrf.token },
        fresh ? [fresh.cookie, csrf.cookie] : [csrf.cookie],
      );
    }

    case 'POST /api/register': {
      const result = await auth.register({
        email: str(body.email),
        password: str(body.password),
        meta,
      });

      if (!result.ok) return failure(res, result);

      return send(res, 202, { status: 'check-your-email' });
    }

    case 'POST /api/login': {
      const result = await auth.login({
        email: str(body.email),
        password: str(body.password),
        rememberMe: body.rememberMe === true,
        deviceToken: auth.readDeviceToken(req.headers.cookie),
        meta,
      });

      if (!result.ok) return failure(res, result);

      if (result.value.kind === 'challenge') {
        return send(res, 200, { challenge: result.value.challenge, methods: result.value.methods });
      }

      const issued = result.value.session;

      return signedIn(res, issued.session, [issued.cookie, issued.deviceCookie]);
    }

    case 'POST /api/verify-email': {
      if (!session)
        return failure(res, { ok: false, code: 'session_expired', reason: 'no_session' });

      const result = await auth.verifyEmailCode({ session, code: str(body.code), meta });

      if (!result.ok) return failure(res, result);

      // Verifying can rotate the session: then the CSRF binding changes too.
      const rotated = result.value.session;

      if (!rotated) return send(res, 200, { verified: true });

      return signedIn(res, rotated.session, [rotated.cookie, rotated.deviceCookie], {
        verified: true,
      });
    }

    case 'POST /api/password-reset/request': {
      const result = await auth.requestPasswordReset({ email: str(body.email), meta });

      if (!result.ok) return failure(res, result);

      // The same answer for every address; the mail, if any, is sent off this path.
      return send(res, 202, { status: 'check-your-email' });
    }

    case 'POST /api/password-reset': {
      const result = await auth.resetPassword({
        token: str(body.token),
        password: str(body.password),
        meta,
      });

      if (!result.ok) return failure(res, result);

      return send(res, 200, { status: 'password-changed' });
    }

    case 'GET /api/me': {
      if (!session)
        return failure(res, { ok: false, code: 'session_expired', reason: 'no_session' });

      return send(res, 200, { user: await stores.users.findById(session.userId) });
    }

    case 'POST /api/logout': {
      const { cookie } = await auth.logout({ token, meta });
      // Signed out again: a new pre-session id and a token bound to it.
      const fresh = newPreSession();
      const csrf = issueCsrfToken(null, fresh.id);

      return send(res, 200, { csrfToken: csrf.token }, [cookie, fresh.cookie, csrf.cookie]);
    }

    default:
      return send(res, 404, { error: { code: 'not_found' } });
  }
}

/** A new session means a new CSRF binding: hand out both. */
function signedIn(
  res: ServerResponse,
  session: StoredSession,
  cookies: CookieSpec[],
  extra: object = {},
): void {
  const csrf = issueCsrfToken(session, null);

  send(res, 200, { ...extra, csrfToken: csrf.token }, [...cookies, csrf.cookie]);
}

createServer((req, res) => {
  handle(req, res).catch((error: unknown) => {
    process.stderr.write(
      `request failed: ${error instanceof Error ? error.stack : String(error)}\n`,
    );

    if (!res.headersSent) send(res, 500, { error: { code: 'internal' } });
  });
}).listen(3000);
