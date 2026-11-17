import { describe, expect, it } from 'vitest';
import { meta, setup } from './setup';

describe('email verification by code (default)', () => {
  it('expires the code after 15 minutes', async () => {
    const env = setup();
    const { session } = await env.signedInUser();
    const code = env.mailer.last('verify-email')?.code ?? '';

    env.clock.advance(15 * 60_000);
    const result = await env.auth.verifyEmailCode({ session, code, meta: meta() });

    expect(!result.ok && result.reason).toBe('verification_expired');
  });

  it('resends to unverified accounts only, within the per-user mail limit', async () => {
    const env = setup();
    const { session } = await env.signedInUser();
    const sends = [];

    for (let i = 0; i < 4; i++)
      sends.push(await env.auth.requestEmailVerification({ session, meta: meta() }));

    expect(sends.map((s) => s.ok)).toEqual([true, true, true, false]);
    const code = env.mailer.last('verify-email')?.code ?? '';
    const verified = await env.auth.verifyEmailCode({ session, code, meta: meta() });

    if (!verified.ok || !verified.value.session) throw new Error('verify failed');

    env.clock.advance(3_600_000);

    const after = await env.auth.requestEmailVerification({
      session: verified.value.session.session,
      meta: meta(),
    });

    expect(after).toEqual({ ok: true, value: { sent: false } });
  });
});
