// The shared CSRF table (packages/auth/tests/adapters/csrf-cases.ts), run
// through createAuthContext on the Node adapter. auth-nestjs runs the same
// rows through CsrfMiddleware, so the two adapters cannot give different
// answers for the same cookies. An unsafe row is answered end to end: a
// mutation behind the `csrf` middleware runs or is refused.
import { isSafeMethod } from '@noctcore/auth';
import { initTRPC, TRPCError } from '@trpc/server';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  buildRequest,
  casesFor,
  expectedOutcome,
  outcome,
  PARITY_CONFIGS,
  type Observed,
  type ParityConfig,
  type ParitySession,
} from '../../auth/tests/adapters/csrf-cases';
import { createAuthMiddlewares, type AuthState } from '../src';
import { createAuthContext } from '../src/context';
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

const t = initTRPC.context<{ auth: AuthState }>().create();
const { csrf } = createAuthMiddlewares(t);
const router = t.router({ change: t.procedure.use(csrf).mutation(() => 'ran') });
const callerFor = t.createCallerFactory(router);

/** True when the mutation ran, false when `csrf` refused it with FORBIDDEN. */
async function mutationRuns(state: AuthState): Promise<boolean> {
  try {
    return (await callerFor({ auth: state }).change()) === 'ran';
  } catch (error) {
    if (error instanceof TRPCError && error.code === 'FORBIDDEN') return false;

    throw error;
  }
}

describe('the CSRF table, through createAuthContext', () => {
  const { auth } = makeAuth();

  const contextFor = (config: ParityConfig) =>
    createAuthContext({ auth, trustedHops: 0, csrf: PARITY_CONFIGS[config] });

  let session: ParitySession;

  beforeAll(async () => {
    const credentials = { email: 'parity@example.com', password: 'correct horse battery' };

    await auth.register({ ...credentials, meta: { ip: '192.0.2.1' } });

    const login = await auth.login({ ...credentials, meta: { ip: '192.0.2.1' } });

    if (!login.ok || login.value.kind !== 'session') throw new Error('sign-in failed');

    const issued = login.value.session;

    session = { id: issued.session.id, cookie: `${auth.cookieName}=${issued.token}` };
  });

  it.each(casesFor('trpc').map((row) => [row.name, row] as const))('%s', async (_name, row) => {
    const request = buildRequest(row, session);
    const res = new Response();

    const { auth: state } = await contextFor(request.config).node({
      req: { method: request.method, headers: { ...request.headers } },
      res,
    });

    const setCookies = ((res.getHeader('set-cookie') ?? []) as string[]).map(
      (line) => line.split('=')[0] as string,
    );

    const seen: Observed = isSafeMethod(row.method)
      ? { setCookies, token: state.csrfToken().csrfToken }
      : { allowed: await mutationRuns(state) };

    expect(outcome(request, seen)).toEqual(expectedOutcome(row));
  });
});
