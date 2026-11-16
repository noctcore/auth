/**
 * Cross-site request forgery: a page on another site makes the browser send a
 * state-changing request with the user's cookies attached.
 *
 * Two checks, both on by default in the framework adapters:
 *
 * 1. `verifyRequestOrigin`: every unsafe method must carry an `Origin` header
 *    naming an allowed origin. Browsers always send it on cross-site requests,
 *    and a page cannot forge it. A missing or `null` Origin is refused.
 * 2. A signed double-submit token for clients the Origin check cannot cover on
 *    its own (a desktop shell on `app://`, old browsers): the server sets a
 *    token cookie, the client echoes it in a header, and the token is an HMAC
 *    over a binding (the session or a pre-session id) under a server secret, so
 *    a token minted for one session is useless in another. Secret rollover:
 *    pass the current secret first and previous ones after it.
 *
 * Guide: Learn, "CSRF".
 */
import { hexDigestsEqual, hmacSha256Hex, secretsEqual } from './hash';
import { cryptoRandom, randomBytes, type RandomSource } from './random';
import { encodeHexLowerCase } from '@oslojs/encoding';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function normalizeOrigin(value: string): string | null {
  try {
    const url = new URL(value);
    // `new URL('app://app').origin` is the string 'null' for non-special
    // schemes, so build scheme://host[:port] by hand.
    return `${url.protocol}//${url.host}`.toLowerCase();
  } catch {
    return null;
  }
}

export function verifyRequestOrigin(input: {
  method: string;
  origin: string | null | undefined;
  allowedOrigins: readonly string[];
}): boolean {
  if (SAFE_METHODS.has(input.method.toUpperCase())) return true;
  if (!input.origin || input.origin === 'null') return false;
  const origin = normalizeOrigin(input.origin);
  if (origin === null) return false;
  return input.allowedOrigins.some((allowed) => normalizeOrigin(allowed) === origin);
}

function mac(secret: Uint8Array, binding: string, nonce: string): string {
  return hmacSha256Hex(secret, `csrf:${binding}:${nonce}`);
}

/** A token `<nonce>.<hmac>` bound to `binding` under the current secret. */
export function createCsrfToken(secret: Uint8Array, binding: string, random: RandomSource = cryptoRandom): string {
  const nonce = encodeHexLowerCase(randomBytes(16, random));
  return `${nonce}.${mac(secret, binding, nonce)}`;
}

export function verifyCsrfToken(input: {
  /** The value of the token cookie. */
  cookieToken: string | null | undefined;
  /** The value the client echoed in the header. */
  headerToken: string | null | undefined;
  binding: string;
  /** Current secret first, then previous ones still accepted during rollover. */
  secrets: readonly Uint8Array[];
}): boolean {
  const { cookieToken, headerToken } = input;
  if (!cookieToken || !headerToken || !secretsEqual(cookieToken, headerToken)) return false;
  const dot = cookieToken.indexOf('.');
  if (dot <= 0) return false;
  const nonce = cookieToken.slice(0, dot);
  const given = cookieToken.slice(dot + 1);
  // Check every secret, without stopping at the first match, so timing does not
  // reveal which secret signed the token.
  let valid = false;
  for (const secret of input.secrets) {
    if (hexDigestsEqual(given, mac(secret, input.binding, nonce))) valid = true;
  }
  return valid;
}
