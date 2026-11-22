/**
 * No secret in a query.
 *
 * tRPC sends a query's input in the URL (`?input=...`), and URLs end up in
 * access logs, proxy logs, browser history, `Referer` headers and HTTP
 * caches. A password, a reset token or a verification code sent that way
 * outlives the request in places nobody audits. So every procedure whose
 * input names a secret must be a mutation, which tRPC sends as a POST body.
 *
 * `findSecretQueries(router)` walks every procedure and lists each query or
 * subscription whose input has a key that names a secret (any word of the
 * key is `password`, `passphrase`, `passcode`, `secret`, `token`, `otp`,
 * `totp`, `hotp`, `code`, `pin` or `pwd`, or its plural, or a run-together
 * name ending in one such as `resettoken`, `otpcode` or `newpin`; the last
 * word is `credential`, `jwt`, `bearer` or `authorization`; or the key holds
 * `apiKey`, `privateKey`, `accessKey`, `signingKey` or `encryptionKey`, at
 * any depth, see `secretKeys` and `isSecretKey`). It fails closed:
 * an input it cannot read (a validator that is not Zod 4, or a Zod schema that
 * can hold any key, such as `z.unknown()` or `z.custom()`) and a lazy router
 * it cannot load synchronously are listed too, unless their path is in
 * `allow`.
 * `assertNoSecretQueries` throws on any finding; call it in a test, or at
 * boot.
 */
import { AuthConfigError } from '@noctcore/auth';
import type { AnyRouter } from '@trpc/server';

/** Words that name a secret on their own: `token`, `password`, `code`. */
const SECRET_WORDS = ['password', 'passwd', 'passphrase', 'passcode', 'secret', 'token', 'totp'];

/**
 * Words too short to match as the ending of a longer word: `code` hides in
 * `postcode`, `barcode` and `unicode`, `pin` in `spin`, `otp` in `hotpot`.
 * They match alone, or after one of `SHORT_SECRET_LEADS` (`otpcode`).
 */
const SHORT_SECRET_WORDS = ['code', 'pin', 'otp', 'hotp', 'pwd'];

/**
 * Leads that turn a short word into a secret when run together with it. A
 * lead such as `new` or `current` adds nothing a camelCase key does not
 * already flag (`newPin` is two words, and `pin` matches alone); it only
 * catches the same name written as one word (`newpin`).
 */
const SHORT_SECRET_LEADS = new Set([
  'otp',
  'totp',
  'hotp',
  'pin',
  'sms',
  'email',
  'verification',
  'verify',
  'auth',
  'authorization',
  'recovery',
  'backup',
  'login',
  'confirm',
  'confirmation',
  'activation',
  'security',
  'access',
  'reset',
  'invite',
  'mfa',
  '2fa',
  'twofactor',
  'new',
  'old',
  'current',
]);

/**
 * Words that name a secret only as the last word of a key: a bare `jwt`,
 * `credentials` or `authorization` carries the secret itself, while
 * `jwtIssuer`, `credentialId` and `authorizationUrl` name something about it.
 */
const TAIL_SECRET_WORDS = ['credential', 'jwt', 'bearer', 'authorization'];

/**
 * Two words that name a secret only together, written as two words or as
 * one: `apiKey`, `privatekey` (a bare `key` is too common, and `publicKey`
 * is no secret).
 */
const SECRET_PAIRS = ['apikey', 'privatekey', 'accesskey', 'signingkey', 'encryptionkey'];

const isUpper = (c: number): boolean => c >= 65 && c <= 90;
const isLower = (c: number): boolean => c >= 97 && c <= 122;
const isDigit = (c: number): boolean => c >= 48 && c <= 57;

/**
 * `currentPassword`, `reset_token`, `OTP-code` → its lower-case words.
 *
 * One pass over the key: a word starts at an upper-case letter that follows
 * a lower-case letter or a digit (`currentPassword`), or that ends a run of
 * capitals before a lower-case letter (`OTPCode`). Each character is looked
 * at once with its two neighbours, so a long key costs linear time; the
 * regular expression this replaces backtracked over every run of capitals.
 */
export function words(key: string): string[] {
  let spaced = '';
  let from = 0;

  for (let i = 1; i < key.length; i++) {
    const current = key.charCodeAt(i);

    if (!isUpper(current)) continue;

    const previous = key.charCodeAt(i - 1);

    const startsWord =
      isLower(previous) ||
      isDigit(previous) ||
      (isUpper(previous) && i + 1 < key.length && isLower(key.charCodeAt(i + 1)));

    if (startsWord) {
      spaced += `${key.slice(from, i)} `;
      from = i;
    }
  }

  return (spaced + key.slice(from))
    .toLowerCase()
    .split(/[^a-z0-9]+/u)
    .filter((word) => word !== '');
}

const singular = (word: string): string => (word.endsWith('s') ? word.slice(0, -1) : word);

/**
 * One lower-case word names a secret when, minus a plural `s`, it is a secret
 * word (`tokens`), ends in a long one (`resettoken`, `accesstokens`), or ends
 * in a short one behind a known lead (`otpcode`, `verificationcode`).
 */
function isSecretWord(word: string): boolean {
  const one = singular(word);

  if (SECRET_WORDS.some((stem) => one.endsWith(stem))) return true;

  return SHORT_SECRET_WORDS.some(
    (stem) =>
      one === stem || (one.endsWith(stem) && SHORT_SECRET_LEADS.has(one.slice(0, -stem.length))),
  );
}

/** A word, or a word run together with the next, that ends in a secret pair. */
const endsInPair = (joined: string): boolean =>
  SECRET_PAIRS.some((pair) => singular(joined).endsWith(pair));

export function isSecretKey(key: string): boolean {
  const parts = words(key);
  const last = singular(parts.at(-1) ?? '');

  return (
    parts.some(isSecretWord) ||
    (last !== '' && TAIL_SECRET_WORDS.some((stem) => last.endsWith(stem))) ||
    parts.some((part, i) => endsInPair(part) || endsInPair(part + (parts[i + 1] ?? '')))
  );
}

interface ZodDef {
  readonly type: string;
  readonly shape?: Readonly<Record<string, unknown>>;
  readonly catchall?: unknown;
  readonly innerType?: unknown;
  readonly in?: unknown;
  readonly out?: unknown;
  readonly options?: readonly unknown[];
  readonly left?: unknown;
  readonly right?: unknown;
  readonly element?: unknown;
  readonly items?: readonly unknown[];
  readonly rest?: unknown;
  readonly keyType?: unknown;
  readonly valueType?: unknown;
  readonly entries?: Readonly<Record<string, unknown>>;
  readonly values?: readonly unknown[];
  readonly getter?: () => unknown;
}

const zodDef = (schema: unknown): ZodDef | undefined =>
  (schema as { _zod?: { def?: ZodDef } } | null | undefined)?._zod?.def;

/**
 * Schemas that hold no keys of their own. A `transform` is one too, on the
 * output side of a pipe (`.transform()`), where it only runs on a value the
 * pipe's input side already read. On the input side (`z.preprocess`) it sees
 * the raw client input first, so that pipe is unreadable (see `secretKeys`).
 */
const LEAVES = new Set([
  'string',
  'number',
  'bigint',
  'boolean',
  'date',
  'enum',
  'literal',
  'nan',
  'never',
  'null',
  'undefined',
  'void',
  'symbol',
  'template_literal',
  'file',
  'transform',
]);

/** Schemas whose children are listed in their def, by the def fields named. */
const CONTAINERS = new Set([
  'object',
  'array',
  'tuple',
  'record',
  'map',
  'set',
  'union',
  'intersection',
  'optional',
  'nullable',
  'default',
  'prefault',
  'catch',
  'readonly',
  'nonoptional',
  'success',
  'promise',
  'pipe',
  'lazy',
]);

/** The values an enum or literal key schema allows, as strings. Zod 4 always sets both fields. */
function keyValues(def: ZodDef | undefined): string[] {
  if (def?.type === 'enum') return Object.values(def.entries as object).map(String);
  if (def?.type === 'literal') return (def.values as readonly unknown[]).map(String);

  return [];
}

/**
 * The secret-named keys anywhere in a Zod 4 schema, or null when the schema
 * holds anything this cannot read. That fails closed: `z.any()`,
 * `z.unknown()` (a loose object's catch-all among them), `z.custom()`,
 * `z.instanceof()`, `z.preprocess()` (its function sees the raw input), a
 * function schema, a type this list does not know (a
 * newer Zod's), and anything that is not Zod 4 all answer null.
 *
 * Every child is walked: object shapes and catch-alls, array elements, tuple
 * items and rest, record and map keys and values, set values, both sides of
 * a union, an intersection and a pipe, wrapped and lazy schemas. A record key
 * schema that is an enum or literal is checked by its values. A record keyed
 * by `z.string()` is readable but accepts any key name; this check cannot
 * know which ones a client will send.
 */
export function secretKeys(schema: unknown, seen = new Set<unknown>()): string[] | null {
  const def = zodDef(schema);

  if (!def) return null;
  if (seen.has(schema)) return [];

  seen.add(schema);

  if (LEAVES.has(def.type)) return [];
  if (!CONTAINERS.has(def.type)) return null;
  // `z.preprocess`: a function reads the raw input before any schema does.
  if (def.type === 'pipe' && zodDef(def.in)?.type === 'transform') return null;

  const children: unknown[] = [];
  const found: string[] = [];

  for (const [key, child] of Object.entries(def.shape ?? {})) {
    if (isSecretKey(key)) found.push(key);

    children.push(child);
  }

  if (def.type === 'record') found.push(...keyValues(zodDef(def.keyType)).filter(isSecretKey));

  children.push(
    def.catchall,
    def.innerType,
    def.in,
    def.out,
    ...(def.options ?? []),
    def.left,
    def.right,
    def.element,
    ...(def.items ?? []),
    def.rest,
    def.keyType,
    def.valueType,
    def.getter?.(),
  );

  for (const child of children) {
    // An absent field, and the null a tuple without a rest holds.
    if (child === undefined || child === null) continue;

    const nested = secretKeys(child, seen);

    if (nested === null) return null;

    found.push(...nested);
  }

  return found;
}

export interface SecretQueryFinding {
  /** The procedure's path, such as `auth.verifyEmail`, or the lazy router's. */
  readonly path: string;
  readonly problem: 'secret_in_query' | 'unreadable_input' | 'lazy_router';
  /** The secret-named keys, for `secret_in_query`. */
  readonly keys: readonly string[];
}

interface ProcedureLike {
  readonly _def: { readonly type: string; readonly inputs: readonly unknown[] };
}

export function findSecretQueries(
  router: AnyRouter,
  options: { allow?: readonly string[] } = {},
): SecretQueryFinding[] {
  const allow = new Set(options.allow ?? []);

  const def = router._def as unknown as {
    readonly procedures: Readonly<Record<string, ProcedureLike>>;
    readonly lazy: Readonly<Record<string, unknown>>;
  };

  const findings: SecretQueryFinding[] = Object.keys(def.lazy)
    .filter((path) => !allow.has(path))
    .map((path) => ({ path, problem: 'lazy_router', keys: [] }));

  for (const [path, procedure] of Object.entries(def.procedures)) {
    if (procedure._def.type === 'mutation' || allow.has(path)) continue;

    const keys: string[] = [];

    for (const input of procedure._def.inputs) {
      const found = secretKeys(input);

      if (found === null) {
        findings.push({ path, problem: 'unreadable_input', keys: [] });
        keys.length = 0;
        break;
      }

      keys.push(...found);
    }

    if (keys.length > 0) findings.push({ path, problem: 'secret_in_query', keys });
  }

  return findings;
}

/** Throws an `AuthConfigError` listing every finding of `findSecretQueries`. */
export function assertNoSecretQueries(
  router: AnyRouter,
  options: { allow?: readonly string[] } = {},
): void {
  const findings = findSecretQueries(router, options);

  if (findings.length === 0) return;

  const lines = findings.map((f) =>
    f.problem === 'secret_in_query'
      ? `${f.path}: a query whose input carries ${f.keys.join(', ')}; make it a mutation`
      : f.problem === 'lazy_router'
        ? `${f.path}: a lazy router this check cannot load; check it on its own or allow it`
        : `${f.path}: an input this check cannot read (not Zod 4, or a schema that takes any key such as z.unknown() or z.custom()); allow it once checked by hand`,
  );

  throw new AuthConfigError(`Secrets must never travel in a query:\n${lines.join('\n')}`);
}
