import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import {
  clientIp,
  serializeCookie,
  toPublicError,
  verifyFetchSite,
  verifyRequestOrigin,
  type AuthFailure,
  type CookieSpec,
  type RequestMeta,
} from '@noctcore/auth';
import { auth } from './auth';

const ORIGIN = 'https://app.example';

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const method = req.method ?? 'GET';
  const route = `${method} ${new URL(req.url ?? '/', ORIGIN).pathname}`;

  const meta: RequestMeta = {
    // trustedHops: the number of proxies in front of this server.
    ip: clientIp({ remoteAddress: req.socket.remoteAddress, trustedHops: 0 }) ?? 'unknown',
    userAgent: req.headers['user-agent'],
    origin: req.headers.origin,
  };

  // CSRF: refuse an unsafe request unless it comes from our own origin. This
  // is the Origin and Sec-Fetch-Site layer only; see the note below the code.
  if (method !== 'GET' && method !== 'HEAD') {
    const secFetchSite = req.headers['sec-fetch-site'];

    const sameOrigin =
      verifyRequestOrigin({ method, origin: req.headers.origin, allowedOrigins: [ORIGIN] }) &&
      (secFetchSite === undefined || verifyFetchSite({ method, secFetchSite }));

    if (!sameOrigin) return send(res, 403, { error: { code: 'forbidden' } });
  }

  const body = await readJson(req);

  switch (route) {
    case 'POST /register': {
      const result = await auth.register({ email: body.email, password: body.password, meta });

      if (!result.ok) return failure(res, result);

      // The same answer whether or not the address was taken.
      return send(res, 202, { status: 'check-your-email' });
    }

    case 'POST /login': {
      const result = await auth.login({
        email: body.email,
        password: body.password,
        deviceToken: auth.readDeviceToken(req.headers.cookie),
        meta,
      });

      if (!result.ok) return failure(res, result);

      // Only a second-factor plugin turns a login into a challenge.
      if (result.value.kind === 'challenge') {
        return send(res, 200, { challenge: result.value.challenge, methods: result.value.methods });
      }

      const { cookie, deviceCookie } = result.value.session;

      return send(res, 200, { ok: true }, [cookie, deviceCookie]);
    }

    case 'POST /logout': {
      const { cookie } = await auth.logout({
        token: auth.readSessionToken(req.headers.cookie),
        meta,
      });

      return send(res, 200, { ok: true }, [cookie]);
    }

    default:
      return send(res, 404, { error: { code: 'not_found' } });
  }
}

/** Only the public code (and a retry time) ever reaches the client. */
function failure(res: ServerResponse, result: AuthFailure): void {
  const error = toPublicError(result);
  const status =
    error.code === 'rate_limited' ? 429 : error.code === 'invalid_credentials' ? 401 : 400;

  send(res, status, { error });
}

function send(
  res: ServerResponse,
  status: number,
  body: unknown,
  cookies: CookieSpec[] = [],
): void {
  res.writeHead(status, {
    'content-type': 'application/json',
    'cache-control': 'no-store',
    ...(cookies.length > 0 ? { 'set-cookie': cookies.map(serializeCookie) } : {}),
  });

  res.end(JSON.stringify(body));
}

/** A small JSON body as strings: anything else becomes an empty string. */
async function readJson(req: IncomingMessage): Promise<{ email: string; password: string }> {
  let raw = '';

  for await (const chunk of req) {
    raw += String(chunk);

    if (raw.length > 16_384) break;
  }

  let parsed: unknown = null;

  try {
    parsed = JSON.parse(raw);
  } catch {
    // Not JSON: treated as empty fields, which the flows refuse.
  }

  const fields = (parsed && typeof parsed === 'object' ? parsed : {}) as Record<string, unknown>;
  const text = (value: unknown) => (typeof value === 'string' ? value : '');

  return { email: text(fields.email), password: text(fields.password) };
}

createServer((req, res) => {
  handle(req, res).catch(() => {
    if (!res.headersSent) send(res, 500, { error: { code: 'internal' } });
  });
}).listen(3000);
