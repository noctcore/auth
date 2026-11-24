// The guides' revoke routes answer the client `{ revoked }` only: the
// `sessionId` that `sessions.revoke` answers is the session's store key, and
// a sample that passed `result.value` through would teach readers to send it
// out (A087). The NestJS guide's own app.test.ts needs Postgres, Redis and
// the generated Prisma client, so the controller is called here directly.
import { describe, expect, it } from 'bun:test';
import { createAuth, type RequestMeta, type StoredSession } from '@noctcore/auth';
import { memoryStores, plainHasher, recordingMailer } from '@noctcore/auth/testing';
import { AccountController } from '../snippets/build/nestjs/account.controller';
import type { AppAuth } from '../snippets/build/node-server/auth';
import { signOutDevice } from '../snippets/learn/signed-in-devices';

const EMAIL = 'ada@example.com';
const PASSWORD = 'correct horse battery';
const meta: RequestMeta = { ip: '203.0.113.7', userAgent: 'test', origin: 'https://app.example' };

type Session = StoredSession<Record<string, never>>;

/** An in-memory auth with one user signed in on two devices. */
async function twoDevices() {
  const auth = createAuth({
    stores: memoryStores(),
    password: { hasher: plainHasher(), breachCheck: false },
    secret: 'test-auth-secret-that-is-32-bytes-or-more',
    urls: { resetPassword: (token) => `https://app.example/reset#${token}` },
    mailer: recordingMailer(),
  });

  await auth.register({ email: EMAIL, password: PASSWORD, meta });

  const signIn = async (): Promise<Session> => {
    const login = await auth.login({ email: EMAIL, password: PASSWORD, meta });

    if (!login.ok || login.value.kind !== 'session') throw new Error('login failed');

    return login.value.session.session;
  };

  const laptop = await signIn();
  const phone = await signIn();

  return { auth: auth as unknown as AppAuth, laptop, phone };
}

describe('the guides answer a revoke with { revoked } only', () => {
  it('in the NestJS account controller', async () => {
    const { auth, laptop, phone } = await twoDevices();
    const controller = new AccountController(auth, {} as never);

    const answer = await controller.revokeSession(
      { handle: auth.sessions.handle(phone.id) },
      laptop,
      meta,
    );

    expect(answer).toEqual({ revoked: true });
  });

  it('in the signed-in devices sample', async () => {
    const { auth, laptop, phone } = await twoDevices();

    const answer = await signOutDevice(auth, {
      current: laptop,
      handle: auth.sessions.handle(phone.id),
      meta,
    });

    expect(answer).toEqual({ revoked: true });
  });
});
