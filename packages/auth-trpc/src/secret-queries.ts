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
 * `totp`, `code` or `pin`, or its plural, or a run-together name ending in
 * one such as `resettoken` or `otpcode`, or `apiKey`, at any depth, see
 * `secretKeys` and `isSecretKey`). It fails closed:
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
const SHORT_SECRET_WORDS = ['code', 'pin', 'otp'];

const SHORT_SECRET_LEADS = new Set([
  'otp',
  'totp',
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
]);

/** Two words that name a secret only together: `apiKey` (a bare `key` is too common). */
const SECRET_PAIRS = new Set(['apikey']);

/** `currentPassword`, `reset_token`, `OTP-code` → its lower-case words. */
function words(key: string): string[] {
  return key
    .replace(/([a-z0-9])([A-Z])/gu, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/gu, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/u)
    .filter((word) => word !== '');
}

/**
 * One lower-case word names a secret when, minus a plural `s`, it is a secret
 * word (`tokens`), ends in a long one (`resettoken`, `accesstokens`), or ends
 * in a short one behind a known lead (`otpcode`, `verificationcode`).
 */
function isSecretWord(word: string): boolean {
  const singular = word.endsWith('s') ? word.slice(0, -1) : word;

  if (SECRET_WORDS.some((stem) => singular.endsWith(stem))) return true;

  return SHORT_SECRET_WORDS.some(
    (stem) =>
      singular === stem ||
      (singular.endsWith(stem) && SHORT_SECRET_LEADS.has(singular.slice(0, -stem.length))),
  );
}

export function isSecretKey(key: string): boolean {
  const parts = words(key);

  return (
    parts.some(isSecretWord) ||
    parts.some((part, i) => SECRET_PAIRS.has(part + (parts[i + 1] ?? '').replace(/s$/u, '')))
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
