// A029: sending a secret in a query, where it lands in URLs and logs.
//
// tRPC puts a query's input in the URL (`?input=...`). A password, a reset
// token or a verification code sent that way is written to access logs, proxy
// logs, browser history and HTTP caches, and leaks through `Referer`. Nothing
// in tRPC stops a procedure that takes a secret from being a query.
//
// Stopped by: auth-trpc src/secret-queries.ts: `assertNoSecretQueries` walks
//   every procedure and fails on a query or subscription whose input names a
//   secret at any depth (shapes, catch-alls, tuple items and rest, record,
//   map and set keys and values, unions, intersections, pipes, wrapped and
//   lazy schemas), on an input it cannot read (any Zod type not on its list,
//   `z.unknown()`, `z.any()`, `z.custom()`) and on a lazy router.
// Learn: Build, "Use with tRPC" (/auth/build/trpc/)
import { initTRPC, lazy } from '@trpc/server';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import {
  assertNoSecretQueries,
  findSecretQueries,
  loginInput,
  verifyEmailLinkInput,
} from '../../src';
import { secretKeys } from '../../src/secret-queries';
import { buildRouter, makeAuth } from '../support';

const t = initTRPC.create();

describe('A029 secret in a query', () => {
  it('refuses a query whose input carries a secret, however it is spelled or nested', () => {
    const router = t.router({
      verify: t.procedure.input(verifyEmailLinkInput).query(() => null),
      login: t.procedure.input(loginInput).query(() => null),
      nested: t.procedure
        .input(z.object({ form: z.object({ reset_token: z.string() }).optional() }))
        .query(() => null),
      piped: t.procedure
        .input(z.object({ OTPCode: z.string() }).transform((v) => v))
        .query(() => null),
      watch: t.procedure.input(z.object({ secret: z.string() })).subscription(async function* () {
        yield await Promise.resolve(1);
      }),
      fine: t.procedure.input(z.object({ id: z.string() })).query(() => null),
      write: t.procedure.input(loginInput).mutation(() => null),
    });

    expect(findSecretQueries(router)).toEqual([
      { path: 'verify', problem: 'secret_in_query', keys: ['token'] },
      { path: 'login', problem: 'secret_in_query', keys: ['password', 'captchaToken'] },
      { path: 'nested', problem: 'secret_in_query', keys: ['reset_token'] },
      { path: 'piped', problem: 'secret_in_query', keys: ['OTPCode'] },
      { path: 'watch', problem: 'secret_in_query', keys: ['secret'] },
    ]);

    expect(() => assertNoSecretQueries(router)).toThrow(
      /verify: a query whose input carries token/u,
    );
  });

  it('fails closed on an input it cannot read and on a lazy router, unless allowed', () => {
    const custom = (value: unknown) => value as { password: string };

    const router = t.router({
      opaque: t.procedure.input(custom).query(() => null),
      later: lazy(async () => Promise.resolve(t.router({}))),
    });

    expect(findSecretQueries(router).map((f) => [f.path, f.problem])).toEqual([
      ['later', 'lazy_router'],
      ['opaque', 'unreadable_input'],
    ]);

    expect(() => assertNoSecretQueries(router)).toThrow(/later: a lazy router/u);
    expect(() => assertNoSecretQueries(router)).toThrow(/opaque: an input this check cannot read/u);
    expect(() => assertNoSecretQueries(router, { allow: ['opaque', 'later'] })).not.toThrow();
  });

  it('finds a secret behind every kind of container', () => {
    const secret = z.object({ password: z.string() });

    const queries = {
      tuple: z.tuple([secret]),
      tupleRest: z.tuple([z.string()]).rest(secret),
      catchall: z.object({}).catchall(secret),
      mapKey: z.map(secret, z.string()),
      mapValue: z.map(z.string(), secret),
      set: z.set(secret),
      recordValue: z.record(z.string(), secret),
      recordEnumKey: z.record(z.enum(['id', 'resetToken']), z.string()),
      recordLiteralKey: z.partialRecord(z.literal('pin'), z.string()),
      array: z.array(secret),
      union: z.union([z.object({ id: z.string() }), secret]),
      intersection: z.intersection(z.object({ id: z.string() }), secret),
      lazy: z.lazy(() => secret),
      wrapped: secret
        .optional()
        .nullable()
        .default({ password: '' })
        .readonly()
        .catch({ password: '' }),
      promise: z.promise(secret),
    };

    const router = t.router(
      Object.fromEntries(
        Object.entries(queries).map(([path, schema]) => [
          path,
          t.procedure.input(schema).query(() => null),
        ]),
      ),
    );

    const findings = findSecretQueries(router);

    expect(findings.map((f) => f.path).sort()).toEqual(Object.keys(queries).sort());
    expect(findings.every((f) => f.problem === 'secret_in_query')).toBe(true);
    expect(findings.find((f) => f.path === 'recordEnumKey')?.keys).toEqual(['resetToken']);
    expect(findings.find((f) => f.path === 'recordLiteralKey')?.keys).toEqual(['pin']);
  });

  it('fails closed on a Zod schema that can carry any key', () => {
    const queries = {
      custom: z.custom<{ password: string }>(),
      instance: z.instanceof(Map),
      unknown: z.unknown(),
      any: z.object({ data: z.any() }),
      loose: z.looseObject({ id: z.string() }),
      preprocessedUnknown: z.preprocess((value) => value, z.unknown()),
      // Its function reads the raw input first: whatever the schema after it says.
      preprocessed: z.preprocess((value) => value, z.object({ id: z.string() })),
    };

    const router = t.router(
      Object.fromEntries(
        Object.entries(queries).map(([path, schema]) => [
          path,
          t.procedure.input(schema as never).query(() => null),
        ]),
      ),
    );

    const findings = findSecretQueries(router);

    expect(findings.map((f) => [f.path, f.problem]).sort()).toEqual(
      Object.keys(queries)
        .sort()
        .map((path) => [path, 'unreadable_input']),
    );

    // A function schema, and a type this walker does not know (as a newer Zod could add).
    expect(secretKeys(z.function())).toBeNull();
    expect(secretKeys({ _zod: { def: { type: 'something_new' } } })).toBeNull();

    // A plain transform reads as what its pipe's input side holds.
    expect(secretKeys(z.object({ id: z.string() }).transform((v) => v.id))).toEqual([]);
  });

  it('passes the documented router, where every secret goes through a mutation', () => {
    expect(() => assertNoSecretQueries(buildRouter(makeAuth().auth))).not.toThrow();
  });
});
