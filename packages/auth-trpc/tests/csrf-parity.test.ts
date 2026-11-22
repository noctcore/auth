// The shared CSRF table (packages/auth/tests/adapters/csrf-cases.ts), run
// through createAuthContext on the Node adapter. auth-nestjs runs the same
// rows through CsrfMiddleware, so the two adapters cannot give different
// answers for the same cookies.
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
import { createAuthContext, internalsOf } from '../src/context';
import { makeAuth } from './support';

class Response {
  readonly headers = new Map<string, number | string | readonly string[]>();

  getHeader(name: string) {
    return this.headers.get(name) as number | string | string[] | undefined;
  }

  setHeader(name: string, value: number | string | readonly string[]) {
    this.headers.set(name, value);
  }
}

describe('the CSRF table, through createAuthContext', () => {
  const { auth } = makeAuth();

  const context = createAuthContext({
    auth,
    trustedHops: 0,
    csrf: { secrets: PARITY_SECRETS, allowedOrigins: [PARITY_ORIGIN] },
  });

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
    const res = new Response();

    const { auth: state } = await context.node({
      req: { method: request.method, headers: { ...request.headers } },
      res,
    });

    const setCookies = ((res.getHeader('set-cookie') ?? []) as string[]).map(
      (line) => line.split('=')[0] as string,
    );

    const seen: Observed =
      row.method === 'POST'
        ? { allowed: internalsOf(state)?.csrfOk === true }
        : { setCookies, token: state.csrfToken().csrfToken };

    expect(outcome(request, seen)).toEqual(expectedOutcome(row));
  });
});
