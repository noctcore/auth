/**
 * One spelling per address. `Alice@Example.com` and `alice@example.com` must be
 * the same account, or registration, login, lockout and reset each see a
 * different user. Normalising once, at the edge of every flow, is the rule.
 */
export type NormalizedEmail = string & { readonly __normalizedEmail: true };

const MAX_LENGTH = 254;
const MAX_LOCAL_LENGTH = 64;
// No whitespace or control characters anywhere; exactly one @.
const FORBIDDEN = /[\s\p{Cc}]/u;

/**
 * Trims, applies Unicode NFC and lowercases. Returns null when the value is not
 * plausibly an address. Deliberately permissive beyond that: the verification
 * mail is the real check.
 */
export function normalizeEmail(input: unknown): NormalizedEmail | null {
  if (typeof input !== 'string') return null;
  const value = input.trim().normalize('NFC').toLowerCase();
  if (value.length === 0 || value.length > MAX_LENGTH || FORBIDDEN.test(value)) return null;
  const at = value.indexOf('@');
  if (at <= 0 || at !== value.lastIndexOf('@')) return null;
  const local = value.slice(0, at);
  const domain = value.slice(at + 1);
  if (local.length > MAX_LOCAL_LENGTH) return null;
  const dot = domain.lastIndexOf('.');
  if (dot <= 0 || dot === domain.length - 1) return null;
  return value as NormalizedEmail;
}
