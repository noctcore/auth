import { createCsrfToken, verifyCsrfToken, verifyFetchSite } from '@noctcore/auth';

// A secret for CSRF only, never the auth secret.
// createCsrfToken refuses one that is too short.
const value = process.env.CSRF_SECRET;

if (!value) throw new Error('Set CSRF_SECRET');

const secret = new TextEncoder().encode(value);

/** Signed in: a token bound to this session, read by the page from a cookie. */
export function csrfToken(sessionId: string): string {
  return createCsrfToken(secret, `session:${sessionId}`);
}

/**
 * Layers two and three, for a POST, PUT, PATCH or DELETE.
 * Layer one is the session cookie's SameSite.
 */
export function csrfAllowed(request: {
  method: string;
  secFetchSite: string | undefined;
  cookieToken: string | undefined;
  headerToken: string | undefined;
  sessionId: string;
}): boolean {
  const sameOrigin = verifyFetchSite({
    method: request.method,
    secFetchSite: request.secFetchSite,
  });

  return (
    sameOrigin &&
    verifyCsrfToken({
      cookieToken: request.cookieToken,
      headerToken: request.headerToken,
      binding: `session:${request.sessionId}`,
      secrets: [secret],
    })
  );
}
