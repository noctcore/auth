/**
 * One spelling per address. `Alice@Example.com` and `alice@example.com` must be
 * the same account, or registration, login, lockout and reset each see a
 * different user. Normalising once, at the edge of every flow, is the rule.
 */
export type NormalizedEmail = string & { readonly __normalizedEmail: true };

const MAX_LENGTH = 254;
const MAX_LOCAL_LENGTH = 64;
// Printable ASCII only, no spaces: refuses control characters and every
// non-ASCII character in the local part and the domain.
const ALLOWED = /^[\x21-\x7e]+$/u;

/** Lowercases A to Z only. `String.prototype.toLowerCase` also folds non-ASCII letters. */
function asciiLower(value: string): string {
  return value.replace(/[A-Z]/gu, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
}

/**
 * Trims and lowercases ASCII letters. Returns null when the value is not
 * plausibly an address, and for any non-ASCII character: Unicode case folding
 * maps distinct characters onto ASCII ones (KELVIN SIGN to `k`, a dotted
 * capital I to `i` plus a combining dot), which would let two different
 * addresses normalise to one account. Internationalised domains must arrive in
 * their ASCII (punycode) form. Deliberately permissive beyond that: the
 * verification mail is the real check.
 */
export function normalizeEmail(input: unknown): NormalizedEmail | null {
  if (typeof input !== 'string') return null;
  const trimmed = input.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_LENGTH || !ALLOWED.test(trimmed)) return null;
  const value = asciiLower(trimmed);
  const at = value.indexOf('@');
  if (at <= 0 || at !== value.lastIndexOf('@')) return null;
  const local = value.slice(0, at);
  const domain = value.slice(at + 1);
  if (local.length > MAX_LOCAL_LENGTH) return null;
  const dot = domain.lastIndexOf('.');
  if (dot <= 0 || dot === domain.length - 1) return null;
  return value as NormalizedEmail;
}
