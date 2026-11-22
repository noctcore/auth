// A106: keeping a previous CSRF secret in use.
//
// During a rollover (`secrets: [NEW, OLD]`) a safe request used to keep any
// cookie that verified under any listed secret, so no client ever moved to
// NEW while OLD was still listed. Removing OLD then broke every client with
// a 403 on its next unsafe request, and after a suspected leak of OLD the
// operator could not shorten the window: nothing migrated while OLD was
// accepted, so OLD stayed as useful to whoever held it as on the day of the
// rotation.
//
// Stopped by: http/csrf-adapter.ts: handOutCsrfToken keeps a cookie only when
//   it verifies under the current secret and mints one under it otherwise;
//   csrfRequestAllowed (doubleSubmitValid) still accepts a previous-secret
//   token a page read before the cookie moved, only while that secret is
//   listed. Parity table: tests/adapters/csrf-cases.ts, run against the core,
//   auth-nestjs and auth-trpc.
// Learn: CSRF (/auth/learn/csrf/); core attacks A008, A100, A101
import { describe, expect, it } from 'vitest';

import { createCsrfToken } from '../../src/http/csrf';
import {
  csrfRequestAllowed,
  handOutCsrfToken,
  resolveCsrfSettings,
  type CsrfContext,
} from '../../src/http/csrf-adapter';

const ORIGIN = 'https://app.test';
const NEW = 'new-csrf-secret-that-is-at-least-32-bytes-long';
const OLD = 'old-csrf-secret-that-is-at-least-32-bytes-long';
const session = { id: 'session-1' };

const context = (secrets: readonly string[]): CsrfContext => ({
  secure: true,
  csrf: resolveCsrfSettings({ secrets, allowedOrigins: [ORIGIN] }, true),
});

const unsafe = (ctx: CsrfContext, cookie: string, header: string): boolean =>
  csrfRequestAllowed(ctx.csrf, {
    session,
    cookies: { preSession: null, token: cookie },
    origin: ORIGIN,
    secFetchSite: 'same-origin',
    headerToken: header,
  });

describe('A106: keeping a previous CSRF secret in use', () => {
  const rollover = context([NEW, OLD]);
  const after = context([NEW]);
  const old = createCsrfToken(new TextEncoder().encode(OLD), `session:${session.id}`);

  it('moves a client off the previous secret on its next safe request', () => {
    const handout = handOutCsrfToken(rollover, {
      session,
      cookies: { preSession: null, token: old },
      sameSite: 'lax',
    });

    expect(handout.token).not.toBe(old);
    expect(handout.cookies.map((cookie) => cookie.value)).toEqual([handout.token]);

    // The previous secret can now go: the new token passes without it.
    expect(unsafe(after, handout.token, handout.token)).toBe(true);
  });

  it('keeps a page that read the old token working only while the old secret is listed', () => {
    const { token } = handOutCsrfToken(rollover, {
      session,
      cookies: { preSession: null, token: old },
      sameSite: 'lax',
    });

    expect(unsafe(rollover, token, old)).toBe(true);
    expect(unsafe(after, token, old)).toBe(false);
    expect(unsafe(after, old, old)).toBe(false);
  });
});
