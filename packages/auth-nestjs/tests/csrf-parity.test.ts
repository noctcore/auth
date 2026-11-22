// The shared CSRF table (packages/auth/tests/adapters/csrf-cases.ts), run
// through CsrfMiddleware. auth-trpc runs the same rows through its context,
// so the two adapters cannot give different answers for the same cookies.
import { beforeAll, describe, expect, it } from 'vitest';
import {
  buildRequest,
  CSRF_CASES,
  expectedOutcome,
  outcome,
  PARITY_ORIGIN,
  PARITY_SECRETS,
  type Observed,
  type ParitySession,
} from '../../auth/tests/adapters/csrf-cases';
import { CsrfMiddleware } from '../src/csrf.middleware';
import { resolveOptions } from '../src/options';
import { handedCsrfToken, type RawResponse } from '../src/request';
import { makeAuth } from './support';

class Response implements RawResponse {
  statusCode = 200;
  readonly headers = new Map<string, number | string | readonly string[]>();

  getHeader(name: string) {
    return this.headers.get(name) as number | string | string[] | undefined;
  }

  setHeader(name: string, value: number | string | readonly string[]) {
    this.headers.set(name, value);
  }

  end() {}
}

describe('the CSRF table, through CsrfMiddleware', () => {
  const { auth } = makeAuth();

  const middleware = new CsrfMiddleware(
    resolveOptions({
      auth,
      trustedHops: 0,
      csrf: { secrets: PARITY_SECRETS, allowedOrigins: [PARITY_ORIGIN] },
    }),
  );

  let session: ParitySession;

  beforeAll(async () => {
    const credentials = { email: 'parity@example.com', password: 'correct horse battery' };

    await auth.register({ ...credentials, meta: { ip: '192.0.2.1' } });

    const login = await auth.login({ ...credentials, meta: { ip: '192.0.2.1' } });

    if (!login.ok || login.value.kind !== 'session') throw new Error('sign-in failed');

    const issued = login.value.session;

    session = { id: issued.session.id, cookie: `${auth.cookieName}=${issued.token}` };
  });

  it.each(CSRF_CASES.map((row) => [row.name, row] as const))('%s', async (_name, row) => {
    const request = buildRequest(row, session);
    const req = { method: request.method, url: '/api/x', headers: { ...request.headers } };
    const res = new Response();
    let passed = false;

    await middleware.use(req, res, () => {
      passed = true;
    });

    const setCookies = ((res.getHeader('set-cookie') ?? []) as string[]).map(
      (line) => line.split('=')[0] as string,
    );

    const seen: Observed =
      row.method === 'POST'
        ? { allowed: passed && res.statusCode === 200 }
        : { setCookies, token: handedCsrfToken(req) ?? '' };

    expect(outcome(request, seen)).toEqual(expectedOutcome(row));
  });
});
