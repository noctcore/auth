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
// The fix must not give a holder of OLD a new way in either. A signed-in
// binding is `session:<session id>`, and the session id (the SHA-256 of the
// session token, the store key) can leak through a store dump or a hook
// payload. A header minted under OLD for that binding, sent over the
// victim's current cookie, is refused: the header must equal the cookie. A
// page that kept the old token in memory gets the same refusal once, and
// reads the token again.
//
// Stopped by: http/csrf-adapter.ts: handOutCsrfToken keeps a cookie only when
//   it verifies under the current secret and mints one under it otherwise;
//   csrfRequestAllowed keeps the strict header-equals-cookie compare. Parity
//   table: tests/adapters/csrf-cases.ts, run against the core, auth-nestjs
//   and auth-trpc.
// Learn: CSRF (/auth/learn/csrf/); core attacks A008, A100, A101
import { describe, expect, it } from 'vitest';

import { sha256Hex } from '../../src/crypto/hash';
import { createCsrfToken } from '../../src/http/csrf';
import {
  csrfRequestAllowed,
  handOutCsrfToken,
  resolveCsrfSettings,
  type CsrfContext,
  type CsrfSessionRef,
} from '../../src/http/csrf-adapter';
import { EMAIL, meta, PASSWORD, registered } from './support';

const ORIGIN = 'https://app.test';
const NEW = 'new-csrf-secret-that-is-at-least-32-bytes-long';
const OLD = 'old-csrf-secret-that-is-at-least-32-bytes-long';
const encoder = new TextEncoder();

const context = (secrets: readonly string[]): CsrfContext => ({
  secure: true,
  csrf: resolveCsrfSettings({ secrets, allowedOrigins: [ORIGIN] }, true),
});

const unsafe = (
  ctx: CsrfContext,
  session: CsrfSessionRef,
  cookie: string,
  header: string,
): boolean =>
  csrfRequestAllowed(ctx.csrf, {
    session,
    cookies: { preSession: null, token: cookie },
    origin: ORIGIN,
    secFetchSite: 'same-origin',
    headerToken: header,
  });

/** A real sign-in, and the session token the browser holds for it. */
async function signedIn(): Promise<{ session: CsrfSessionRef; token: string }> {
  const { auth } = await registered();
  const login = await auth.login({ email: EMAIL, password: PASSWORD, meta: meta() });

  if (!login.ok || login.value.kind !== 'session') throw new Error('sign-in failed');

  return { session: login.value.session.session, token: login.value.session.token };
}

describe('A106: keeping a previous CSRF secret in use', () => {
  const rollover = context([NEW, OLD]);
  const after = context([NEW]);

  it('moves a client off the previous secret on its next safe request', async () => {
    const { session } = await signedIn();
    const old = createCsrfToken(encoder.encode(OLD), `session:${session.id}`);

    const handout = handOutCsrfToken(rollover, {
      session,
      cookies: { preSession: null, token: old },
      sameSite: 'lax',
    });

    expect(handout.token).not.toBe(old);
    expect(handout.cookies.map((cookie) => cookie.value)).toEqual([handout.token]);

    // The previous secret can now go: the new token passes without it.
    expect(unsafe(after, session, handout.token, handout.token)).toBe(true);
  });

  it('refuses an old-secret header over the current cookie, kept by a page or minted', async () => {
    const { session, token: sessionToken } = await signedIn();
    const old = createCsrfToken(encoder.encode(OLD), `session:${session.id}`);

    const { token } = handOutCsrfToken(rollover, {
      session,
      cookies: { preSession: null, token: old },
      sameSite: 'lax',
    });

    // A page that read the old token before the cookie moved: refused once.
    expect(unsafe(rollover, session, token, old)).toBe(false);

    // Someone holding OLD who learned the session id (the store key, the
    // SHA-256 of the session token) mints a header for the victim's binding.
    expect(session.id).toBe(sha256Hex(sessionToken));

    const minted = createCsrfToken(encoder.encode(OLD), `session:${sha256Hex(sessionToken)}`);

    expect(unsafe(rollover, session, token, minted)).toBe(false);

    // The old pair itself passes only while OLD is listed.
    expect(unsafe(rollover, session, old, old)).toBe(true);
    expect(unsafe(after, session, old, old)).toBe(false);
  });
});
