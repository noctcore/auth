import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createAuth } from '@noctcore/auth';
import { memoryStores, plainHasher, recordingMailer } from '@noctcore/auth/testing';
import { assertNoSecretQueries, assertProceduresGuarded } from '@noctcore/auth-trpc';
import type { AppAuth } from '../node-server/auth.ts';
import { createFetchHandler } from './fetch.ts';
import { createAppRouter } from './router.ts';

const ORIGIN = 'http://localhost:3000';

// The same flows over in-memory stores, so the test needs no Redis or Postgres.
const auth = createAuth({
  stores: memoryStores(),
  password: { hasher: plainHasher(), breachCheck: false },
  session: { cookie: { secure: false } },
  secret: 'test-auth-secret-that-is-32-bytes-or-more',
  urls: { resetPassword: (token) => `${ORIGIN}/reset-password#${token}` },
  mailer: recordingMailer(),
}) as unknown as AppAuth;

test('every procedure has an access rule, and no query carries a secret', () => {
  const router = createAppRouter(auth);

  assertProceduresGuarded(router);
  assertNoSecretQueries(router);
});

test('a mutation without the CSRF token is refused, and passes with it', async () => {
  const handle = createFetchHandler(auth, {
    csrfSecret: 'test-csrf-secret-that-is-32-bytes-or-more',
    origin: ORIGIN,
  });

  // The first query hands out the pre-session and CSRF cookies.
  const first = await handle(new Request(`${ORIGIN}/trpc/session`), '127.0.0.1');
  const cookies = first.headers.getSetCookie().map((line) => line.split(';')[0] ?? '');
  const csrf = cookies.find((c) => c.startsWith('csrf='))?.slice('csrf='.length) ?? '';

  const register = (headers: Record<string, string>) =>
    handle(
      new Request(`${ORIGIN}/trpc/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: ORIGIN, ...headers },
        body: JSON.stringify({ email: 'ada@example.com', password: 'correct horse battery' }),
      }),
      '127.0.0.1',
    );

  assert.equal((await register({ cookie: cookies.join('; ') })).status, 403);
  assert.equal((await register({ cookie: cookies.join('; '), 'x-csrf-token': csrf })).status, 200);
});
