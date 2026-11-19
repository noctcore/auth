/**
 * One spelling per address. `Alice@Example.com` and `alice@example.com` must be
 * the same account, or registration, login, lockout and reset each see a
 * different user. Normalising once, at the edge of every flow, with the one
 * normaliser `createAuth` resolved from `email.normalize`, is the rule: every
 * comparison, every stored address and every counter key derived from an
 * address goes through it.
 */
import { AuthConfigError } from './errors';

export type NormalizedEmail = string & { readonly __normalizedEmail: true };

/**
 * The built-in policies for `email.normalize`.
 *
 * - `standard` (the default): trims, lowercases A to Z, refuses every
 *   non-ASCII character (answered `invalid_email`). Internationalised domains
 *   must arrive as punycode.
 * - `ascii`: the same output as `standard`, but an address with a non-ASCII
 *   character is answered with its own code, `email_not_ascii`, so the app can
 *   tell the user to use an ASCII address instead of "invalid".
 * - `unicode`: NFC, then lowercases the whole address (domain and local part)
 *   with Unicode case mapping, the final sigma folded to the plain one in
 *   the local part (a domain keeps a typed final sigma, as IDNA2008 does).
 *   Refuses invisible and control characters, compatibility characters
 *   (fullwidth letters, ligatures), punycode labels, any part that mixes
 *   scripts (a Cyrillic letter among Latin ones), and a few Latin letters
 *   that read as other Latin ones (the dotless i, the IPA Extensions block,
 *   a dot above on i or j). There is no UTS 39 confusables check, so other
 *   lookalikes within one script are accepted.
 */
export type EmailPolicy = 'standard' | 'ascii' | 'unicode';

/**
 * A custom normaliser. Gets the raw input (a string) and returns the one
 * spelling to compare and store, or null for an address it refuses. It must be
 * pure, deterministic and idempotent: `normalize(normalize(x)) === normalize(x)`.
 * `createAuth` checks that on a sample at startup and every result again on
 * each call, and refuses an address whose result is not a fixed point.
 */
export type EmailNormalizer = (email: string) => string | null;

/** Why an address was refused: the reason, and the public code it is answered with. */
export type EmailRefusal = 'invalid_email' | 'email_not_ascii';

export type EmailVerdict =
  | { readonly ok: true; readonly email: NormalizedEmail }
  | { readonly ok: false; readonly reason: EmailRefusal };

/** The normaliser `createAuth` resolved: every flow compares and stores through it. */
export type ResolvedEmailNormalizer = (input: unknown) => EmailVerdict;

const MAX_LENGTH = 254;
const MAX_LOCAL_LENGTH = 64;
// Printable ASCII only, no spaces: refuses control characters and every
// non-ASCII character in the local part and the domain.
const ALLOWED = /^[\x21-\x7e]+$/u;
const NON_ASCII = /[^\p{ASCII}]/u;
const INVALID: EmailVerdict = { ok: false, reason: 'invalid_email' };
const NOT_ASCII: EmailVerdict = { ok: false, reason: 'email_not_ascii' };

/** Lowercases A to Z only. `String.prototype.toLowerCase` also folds non-ASCII letters. */
function asciiLower(value: string): string {
  return value.replace(/[A-Z]/gu, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
}

function accepted(email: string): EmailVerdict {
  return { ok: true, email: email as NormalizedEmail };
}

/**
 * The `standard` policy as a plain function: trims and lowercases ASCII
 * letters. Returns null when the value is not plausibly an address, and for
 * any non-ASCII character: Unicode case folding maps distinct characters onto
 * ASCII ones (KELVIN SIGN to `k`, a dotted capital I to `i` plus a combining
 * dot), which would let two different addresses normalise to one account.
 * Internationalised domains must arrive in their ASCII (punycode) form.
 * Deliberately permissive beyond that: the verification mail is the real check.
 *
 * With `email.normalize` set to another policy this is no longer the
 * normaliser your auth uses: call `auth.normalizeEmail` in your own code (an
 * admin create, an import) so it matches what the flows store.
 *
 * This is stricter than NFC plus Unicode lowercasing, and it changes existing
 * data: an app adopting the package with stored addresses that contain any
 * non-ASCII character (an accented local part, a Unicode domain) must find
 * them first (for example `WHERE email ~ '[^ -~]'` in PostgreSQL), or pick the
 * `unicode` policy.
 */
export function normalizeEmail(input: unknown): NormalizedEmail | null {
  const verdict = standardPolicy(input);

  return verdict.ok ? verdict.email : null;
}

function standardPolicy(input: unknown): EmailVerdict {
  if (typeof input !== 'string') return INVALID;

  const trimmed = input.trim();

  if (trimmed.length === 0 || trimmed.length > MAX_LENGTH || !ALLOWED.test(trimmed)) return INVALID;

  const value = asciiLower(trimmed);
  const at = value.indexOf('@');

  if (at <= 0 || at !== value.lastIndexOf('@')) return INVALID;

  const local = value.slice(0, at);
  const domain = value.slice(at + 1);

  if (local.length > MAX_LOCAL_LENGTH) return INVALID;

  const dot = domain.lastIndexOf('.');

  if (dot <= 0 || dot === domain.length - 1) return INVALID;

  return accepted(value);
}

function asciiPolicy(input: unknown): EmailVerdict {
  if (typeof input === 'string' && NON_ASCII.test(input.trim())) return NOT_ASCII;

  return standardPolicy(input);
}

// Characters no address may carry under the unicode policy: controls, format
// characters (bidi overrides, zero-width joiners), surrogates, private use,
// unassigned code points, separators and everything default-ignorable, so two
// addresses that render the same cannot differ by an invisible character.
const FORBIDDEN = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Z}\p{Default_Ignorable_Code_Point}]/u;
const NEUTRAL = /[\p{Script=Common}\p{Script=Inherited}]/u;

// Latin letters that read as other Latin letters, which the one-script rule
// cannot see because the lookalike and the original share a script: the
// dotless `\u0131` (reads as `i`), the IPA Extensions block (`\u0251` reads
// as `a`, `\u0261` as `g`), and a combining dot above on `i` or `j`, which
// is also what `\u0130` lowercases to (`i` followed by `\u0307`). Checked
// after lowercasing and on the decomposed form, so a capital form, or a dot
// above on a precomposed `i` with another mark (NFC writes `i` and
// `\u0323` as one letter), is refused too. This is a short list, not a
// UTS 39 confusables check: other same-script lookalikes are accepted (see
// THREAT_MODEL.md).
const LATIN_LOOKALIKE = /[\u0131\u0250-\u02AF]|[ij]\p{Mn}*\u0307/u;

// The scripts told apart; a letter of any other script counts as 'Other'.
const SCRIPT_PATTERNS: ReadonlyArray<readonly [string, RegExp]> = [
  ['Latin', /\p{Script=Latin}/u],
  ['Greek', /\p{Script=Greek}/u],
  ['Cyrillic', /\p{Script=Cyrillic}/u],
  ['Armenian', /\p{Script=Armenian}/u],
  ['Hebrew', /\p{Script=Hebrew}/u],
  ['Arabic', /\p{Script=Arabic}/u],
  ['Syriac', /\p{Script=Syriac}/u],
  ['Thaana', /\p{Script=Thaana}/u],
  ['Devanagari', /\p{Script=Devanagari}/u],
  ['Bengali', /\p{Script=Bengali}/u],
  ['Gurmukhi', /\p{Script=Gurmukhi}/u],
  ['Gujarati', /\p{Script=Gujarati}/u],
  ['Oriya', /\p{Script=Oriya}/u],
  ['Tamil', /\p{Script=Tamil}/u],
  ['Telugu', /\p{Script=Telugu}/u],
  ['Kannada', /\p{Script=Kannada}/u],
  ['Malayalam', /\p{Script=Malayalam}/u],
  ['Sinhala', /\p{Script=Sinhala}/u],
  ['Thai', /\p{Script=Thai}/u],
  ['Lao', /\p{Script=Lao}/u],
  ['Tibetan', /\p{Script=Tibetan}/u],
  ['Myanmar', /\p{Script=Myanmar}/u],
  ['Georgian', /\p{Script=Georgian}/u],
  ['Hangul', /\p{Script=Hangul}/u],
  ['Ethiopic', /\p{Script=Ethiopic}/u],
  ['Cherokee', /\p{Script=Cherokee}/u],
  ['Khmer', /\p{Script=Khmer}/u],
  ['Mongolian', /\p{Script=Mongolian}/u],
  ['Hiragana', /\p{Script=Hiragana}/u],
  ['Katakana', /\p{Script=Katakana}/u],
  ['Bopomofo', /\p{Script=Bopomofo}/u],
  ['Han', /\p{Script=Han}/u],
];

// The script mixes Unicode's "highly restrictive" profile (UTS 39) allows:
// Japanese, Chinese and Korean writing with Latin. Any other mix is refused.
const ALLOWED_MIXES: ReadonlyArray<ReadonlySet<string>> = [
  new Set(['Latin', 'Han', 'Hiragana', 'Katakana']),
  new Set(['Latin', 'Han', 'Bopomofo']),
  new Set(['Latin', 'Han', 'Hangul']),
];

function scriptOf(char: string): string | null {
  if (NEUTRAL.test(char)) return null;

  for (const [name, pattern] of SCRIPT_PATTERNS) if (pattern.test(char)) return name;

  return 'Other';
}

/** One script per part (digits and punctuation belong to none), or an allowed CJK mix. */
function isSingleScript(part: string): boolean {
  const scripts = new Set<string>();

  for (const char of part) {
    const script = scriptOf(char);

    if (script) scripts.add(script);
  }

  if (scripts.size <= 1) return true;
  if (scripts.has('Other')) return false;

  return ALLOWED_MIXES.some((mix) => [...scripts].every((script) => mix.has(script)));
}

const encoder = new TextEncoder();

function octets(value: string): number {
  return encoder.encode(value).length;
}

/** Whether the URL standard (UTS 46 processing) accepts the domain as a host. */
function isValidHost(domain: string): boolean {
  try {
    return new URL(`http://${domain}/`).hostname.length > 0;
  } catch {
    return false;
  }
}

function unicodeOnce(trimmed: string): string | null {
  if (trimmed.length === 0 || FORBIDDEN.test(trimmed)) return null;

  const composed = trimmed.normalize('NFC');
  const at = composed.indexOf('@');

  if (at <= 0 || at !== composed.lastIndexOf('@')) return null;

  // The local part: lowercased, with the final sigma folded to the plain one
  // as Unicode case folding does. `toLowerCase` writes a capital sigma at the
  // end of a word as the final form, so `\u03A3` and `\u03C3` would
  // otherwise be two spellings of one mailbox depending on what follows.
  const local = composed
    .slice(0, at)
    .toLowerCase()
    .replace(/\u03C2/gu, '\u03C3')
    .normalize('NFC');

  // The domain: a typed final sigma stays, because IDNA2008 treats `\u03C2` as
  // its own letter, but a capital sigma always lowercases to the plain one (as
  // UTS 46 maps it), whatever follows it.
  const domain = composed
    .slice(at + 1)
    .replace(/\u03A3/gu, '\u03C3')
    .toLowerCase()
    .normalize('NFC');

  const value = `${local}@${domain}`;

  // Compatibility characters (fullwidth `\uFF41`, the `\uFB01` ligature,
  // superscripts) render like other letters but are distinct code points:
  // refused, so the stored form is the only spelling that reads that way.
  if (value.normalize('NFKC') !== value || octets(value) > MAX_LENGTH) return null;
  if (LATIN_LOOKALIKE.test(value.normalize('NFD'))) return null;

  const labels = domain.split('.');

  if (octets(local) > MAX_LOCAL_LENGTH || labels.length < 2) return null;

  // A punycode label is a second spelling of a Unicode one: `xn--bcher-kva`
  // and `bücher` would be two accounts for one mailbox. Unicode form only.
  for (const label of labels)
    if (label.length === 0 || label.startsWith('xn--') || !isSingleScript(label)) return null;

  if (!isSingleScript(local) || !isValidHost(labels.join('.'))) return null;

  return value;
}

function unicodePolicy(input: unknown): EmailVerdict {
  if (typeof input !== 'string') return INVALID;

  const value = unicodeOnce(input.trim());

  // Lowercasing can leave a string NFC would compose differently on a second
  // pass; only a fixed point is accepted, so the policy is idempotent by
  // construction.
  return value !== null && unicodeOnce(value) === value ? accepted(value) : INVALID;
}

const POLICIES: Readonly<Record<EmailPolicy, ResolvedEmailNormalizer>> = {
  standard: standardPolicy,
  ascii: asciiPolicy,
  unicode: unicodePolicy,
};

// What a custom normaliser's output may never contain: control characters,
// line separators and whitespace (the address goes into mail headers), and
// the commas and angle brackets that would make it a list of recipients.
const UNSAFE_OUTPUT = /[\p{Cc}\p{White_Space}\u2028\u2029,<>]/u;

/** One `@` with something on each side, nothing unsafe, at most 254 bytes. */
function isUsableOutput(value: unknown): value is string {
  if (typeof value !== 'string' || UNSAFE_OUTPUT.test(value)) return false;

  const at = value.indexOf('@');

  return (
    at > 0 && at === value.lastIndexOf('@') && at < value.length - 1 && octets(value) <= MAX_LENGTH
  );
}

/** Addresses a custom normaliser is tried on at startup: case, IDN, NFD, confusables, junk. */
const BOOT_SAMPLE = [
  'alice@example.com',
  '  Alice.Smith+Tag@Example.COM ',
  'ALICE@EXAMPLE.COM',
  'zo\u00EB@b\u00FCcher.de',
  'zoe\u0308@bu\u0308cher.de',
  'ZO\u00CB@B\u00DCCHER.DE',
  'user@xn--bcher-kva.de',
  '\u0430lice@example.com',
  '\u212Aelvin@example.com',
  '\u0130stanbul@example.com',
  'stra\u00DFe@example.de',
  'STRASSE@example.de',
  '\uFF41lice@example.com',
  'al\u200Bice@example.com',
  '"quoted"@example.com',
  'not-an-address',
  '',
  'a@b',
];

// Different mailboxes a custom normaliser must keep apart when it accepts both:
// another local part, another domain. A constant or domain-only normaliser
// would merge every account into one.
const DISTINCT_MAILBOXES: ReadonlyArray<readonly [string, string]> = [
  ['alice@example.com', 'bob@example.com'],
  ['alice@example.com', 'alice@example.org'],
];

function describeSample(index: number): string {
  return `the startup sample address #${index}`;
}

/**
 * Checks a custom normaliser on the startup sample: it must not throw, must
 * answer a usable string or null, the same answer twice, and a fixed point.
 */
function checkCustomNormalizer(normalize: EmailNormalizer): void {
  BOOT_SAMPLE.forEach((sample, index) => {
    let first: unknown;
    let second: unknown;

    try {
      first = normalize(sample);
      second = normalize(sample);
    } catch (error) {
      throw new AuthConfigError(
        `email.normalize threw on ${describeSample(index)}: return null for an address it refuses`,
        { cause: error },
      );
    }

    if (first === null && second === null) return;

    if (!isUsableOutput(first))
      throw new AuthConfigError(
        `email.normalize must return null or an address with exactly one @, a non-empty local part and domain, no whitespace, commas, angle brackets or control characters, at most ${MAX_LENGTH} bytes (${describeSample(index)})`,
      );

    if (second !== first)
      throw new AuthConfigError(
        `email.normalize must be deterministic: two calls gave different results for ${describeSample(index)}`,
      );

    let again: unknown;

    try {
      again = normalize(first);
    } catch (error) {
      throw new AuthConfigError(
        `email.normalize threw on its own output for ${describeSample(index)}`,
        { cause: error },
      );
    }

    if (again !== first)
      throw new AuthConfigError(
        `email.normalize must be idempotent: normalize(normalize(x)) differs from normalize(x) for ${describeSample(index)}`,
      );
  });

  for (const [one, other] of DISTINCT_MAILBOXES) {
    const a = normalize(one);
    const b = normalize(other);

    if (a !== null && a === b)
      throw new AuthConfigError(
        `email.normalize must keep different mailboxes apart: ${one} and ${other} gave the same result`,
      );
  }
}

/**
 * Hears about a custom normaliser that misbehaves after startup. Gets a fixed
 * message and, for a throw, only the error's class name: the error's own
 * message could quote the address.
 */
export type EmailNormalizerErrorHandler = (
  message: string,
  details?: { readonly errorName: string },
) => void;

function errorName(error: unknown): string {
  return error instanceof Error ? error.constructor.name : typeof error;
}

function customPolicy(
  normalize: EmailNormalizer,
  onError: EmailNormalizerErrorHandler,
): ResolvedEmailNormalizer {
  return (input) => {
    if (typeof input !== 'string') return INVALID;

    try {
      const value = normalize(input);

      if (value === null) return INVALID;

      if (!isUsableOutput(value)) {
        onError('email.normalize returned an unusable value; refusing the address');

        return INVALID;
      }

      // Every stored address is normalised again when it is compared: a
      // result that is not a fixed point would stop matching itself.
      if (normalize(value) !== value) {
        onError('email.normalize is not idempotent for an address; refusing it');

        return INVALID;
      }

      return accepted(value);
    } catch (error) {
      onError('email.normalize threw; refusing the address', { errorName: errorName(error) });

      return INVALID;
    }
  };
}

/**
 * Resolves `email.normalize` into the one normaliser every flow uses. Throws
 * `AuthConfigError` for an unknown policy name, and for a custom function
 * that fails the startup checks. `onError` hears about a custom normaliser
 * that misbehaves later: a fixed message and at most the error's class name,
 * never the address or the error's message.
 */
export function resolveEmailNormalizer(
  option: EmailPolicy | EmailNormalizer | undefined,
  onError: EmailNormalizerErrorHandler,
): ResolvedEmailNormalizer {
  if (option === undefined) return standardPolicy;

  if (typeof option === 'function') {
    checkCustomNormalizer(option);

    return customPolicy(option, onError);
  }

  if (typeof option === 'string' && Object.hasOwn(POLICIES, option)) return POLICIES[option];

  throw new AuthConfigError(
    `email.normalize must be 'standard', 'ascii', 'unicode' or a function, got ${JSON.stringify(option)}`,
  );
}
