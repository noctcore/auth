// A023: holding responses up through a slow or hung mailer.
//
// A mailer that is slow, or never settles, delays every answer that waits for
// it: a mail outage stalls sign-up, and a door that mails on one branch only
// (a new address, a known one) answers slower on that branch, which an attacker
// can time. Each flow hands its mail to the mailer and answers without waiting
// for delivery.
//
// Stopped by: core/auth-core.ts (`mail` calls `mailer.send` through `background`
//   and never awaits it), core/background.ts, flows/register.ts,
//   flows/email-verification.ts, flows/password-change.ts, flows/password-reset.ts,
//   flows/password-reset-request.ts, flows/lock-notice.ts. Bounded by Vitest's
//   fake timers, not the wall clock.
// Learn: Enumeration (/auth/learn/enumeration/)
import { describe, expect, it } from 'vitest';

import {
  EMAIL,
  hangMailer,
  linkFor,
  meta,
  NEW_PASSWORD,
  onFakeClock,
  PASSWORD,
  queued,
  registered,
  setup,
} from './support';
import type { Logger } from '../../src';

const handedTypes = (handed: ReadonlyArray<{ type: string }>) => handed.map((m) => m.type);

describe('A023: holding responses up through a slow or hung mailer', () => {
  it('answers a sign-up for a new address while its verification mail never settles', async () => {
    const env = setup();
    const { handed } = hangMailer(env.mailer);

    const answer = await onFakeClock(() =>
      env.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() }),
    );

    expect(answer).toEqual({ ok: true, value: { session: null } });
    expect(handedTypes(handed)).toEqual(['verify-email']);
  });

  it('answers a sign-up for a taken address while its "account exists" mail never settles', async () => {
    const env = await registered();
    const { handed } = hangMailer(env.mailer);

    const answer = await onFakeClock(() =>
      env.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() }),
    );

    expect(answer).toEqual({ ok: true, value: { session: null } });
    expect(handedTypes(handed)).toEqual(['account-exists']);
  });

  it('answers a reset request, and finishes the reset job, while the reset mail never settles', async () => {
    const detached = await registered();
    const fromDetached = hangMailer(detached.mailer);

    const answer = await onFakeClock(() =>
      detached.auth.requestPasswordReset({ email: EMAIL, meta: meta() }),
    );

    expect(answer).toEqual({ ok: true, value: undefined });
    expect(handedTypes(fromDetached.handed)).toEqual(['password-reset']);

    // With a queue, the worker's job finishes too, so a hung mailer does not
    // pin a worker slot.
    const t = queued();

    await t.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });
    await t.auth.requestPasswordReset({ email: EMAIL, meta: meta() });

    const fromWorker = hangMailer(t.mailer);
    const job = await onFakeClock(() => t.drain());

    expect(job).toBeUndefined();
    expect(handedTypes(fromWorker.handed)).toEqual(['password-reset']);
  });

  it('answers a request for another verification mail while that mail never settles', async () => {
    const env = setup();
    const { session } = await env.signedInUser(EMAIL);
    const { handed } = hangMailer(env.mailer);

    const answer = await onFakeClock(() =>
      env.auth.requestEmailVerification({ session, meta: meta() }),
    );

    expect(answer).toEqual({ ok: true, value: { sent: true } });
    expect(handedTypes(handed)).toEqual(['verify-email']);
  });

  it('answers a password change while the "password changed" mail never settles', async () => {
    const env = setup();
    const { session } = await env.signedInUser(EMAIL);
    const { handed } = hangMailer(env.mailer);

    const answer = await onFakeClock(() =>
      env.auth.changePassword({
        session,
        currentPassword: PASSWORD,
        newPassword: NEW_PASSWORD,
        meta: meta(),
      }),
    );

    expect(answer !== 'held up' && answer.ok).toBe(true);
    expect(handedTypes(handed)).toEqual(['password-changed']);
  });

  it('answers a completed password reset while the "password changed" mail never settles', async () => {
    const t = queued();

    await t.signedInUser(EMAIL);

    const token = await linkFor(t);
    const { handed } = hangMailer(t.mailer);

    const answer = await onFakeClock(() =>
      t.auth.resetPassword({ token, password: NEW_PASSWORD, meta: meta() }),
    );

    expect(answer).toEqual({ ok: true, value: undefined });
    expect(handedTypes(handed)).toEqual(['password-changed']);
  });

  it('hands each mail over at most once: a failing send is logged, never retried', async () => {
    const failures: string[] = [];

    const logger: Logger = {
      warn: () => undefined,
      error: (message) => void failures.push(message),
    };

    let sends = 0;

    const env = setup({
      logger,
      mailer: {
        send: async () => {
          sends++;
          throw new Error('smtp down');
        },
      },
    } as never);

    const answer = await env.auth.register({ email: EMAIL, password: PASSWORD, meta: meta() });

    expect(answer.ok).toBe(true);
    expect(sends).toBe(1);
    expect(failures).toEqual(['Mailer failed']);
  });
});
