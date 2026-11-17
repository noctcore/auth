import { describe, expect, it } from 'vitest';

import { hmacSha256Hex } from '../../src/crypto/hash';
import { setup } from '../flows/setup';

describe('plugin context', () => {
  it('derives a keyed hash per purpose from the server secret, never the secret itself', () => {
    const { auth } = setup();
    const { context } = auth;
    const a = context.keyedHash('purpose-a', 'message');

    expect(a).toMatch(/^[0-9a-f]{64}$/u);
    expect(context.keyedHash('purpose-a', 'message')).toBe(a);
    expect(context.keyedHash('purpose-b', 'message')).not.toBe(a);
    expect(context.keyedHash('purpose-a', 'other')).not.toBe(a);

    expect(a).not.toBe(
      hmacSha256Hex(
        new TextEncoder().encode('test-secret-that-is-at-least-32-bytes-long'),
        'message',
      ),
    );

    expect(
      setup({ secret: 'another-secret-that-is-at-least-32-bytes' }).auth.context.keyedHash(
        'purpose-a',
        'message',
      ),
    ).not.toBe(a);
  });

  it('checks fresh authentication against session.freshAuthAge', async () => {
    const t = setup({ session: { freshAuthAge: '5m' } });
    const { session } = await t.signedInUser();

    expect(t.auth.context.requireFreshAuth(session)).toEqual({ ok: true, value: undefined });
    t.clock.advance(5 * 60_000);
    expect(t.auth.context.requireFreshAuth(session)).toEqual({ ok: true, value: undefined });
    t.clock.advance(1);

    expect(t.auth.context.requireFreshAuth(session)).toEqual({
      ok: false,
      code: 'fresh_auth_required',
      reason: 'stale_authentication',
    });
  });

  it('hands plugins the session cookie config', () => {
    const { auth } = setup({ session: { cookie: { name: 'sid', secure: false } } });

    expect(auth.context.cookie).toEqual({ name: 'sid', secure: false });
  });
});
