// Ties the Build guides that follow the Build template (see
// src/components/docs/README.md) to their code samples and to the package:
// the page order, the wiring diagrams' steps and codes, and the anchors other
// pages link to. Add a guide to GUIDES when it moves to the template.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'bun:test';
import { DIAGRAMS, SITE, source } from './learn-checks';

const BUILD = join(SITE, 'src/content/docs/build');

/** Each guide on the template, with its wiring diagram and the anchors linked from elsewhere. */
const GUIDES = {
  'node-server': { diagram: 'NodeServerWiring', anchors: ['csrf'] },
  trpc: {
    diagram: 'TrpcWiring',
    anchors: [
      'the-router',
      'the-client',
      'verification-links',
      'rate-limit-tiers-per-user-keys-and-exemptions',
    ],
  },
} as const;

const guide = (slug: string) => readFileSync(join(BUILD, `${slug}.mdx`), 'utf8');
const diagram = (name: string) => readFileSync(join(DIAGRAMS, `${name}.astro`), 'utf8');
const sample = (path: string) => readFileSync(join(SITE, 'snippets/build', path), 'utf8');

/** The slug Starlight gives a heading. */
const slugOf = (heading: string) =>
  heading
    .toLowerCase()
    .replace(/[^a-z0-9 -]/gu, '')
    .trim()
    .replace(/ +/gu, '-');

/** Positions of `needles` in `text`; each must be there. */
function positions(text: string, needles: readonly string[]): number[] {
  return needles.map((needle) => {
    const at = text.indexOf(needle);

    expect(at, needle).toBeGreaterThan(-1);

    return at;
  });
}

const ascending = (values: readonly number[]) =>
  values.every((value, i) => i === 0 || value > (values[i - 1] ?? -1));

describe('Build guide template', () => {
  for (const [slug, { diagram: name, anchors }] of Object.entries(GUIDES)) {
    const text = guide(slug);

    it(`${slug}: summary, wiring diagram, steps and "Check it works", in that order`, () => {
      expect(
        ascending(
          positions(text, [
            '<GuideSummary>',
            '## How the pieces fit',
            `<${name} />`,
            '## Build it',
            '<Steps>',
            '</Steps>',
            '## Check it works',
          ]),
        ),
      ).toBe(true);
      expect(text).toContain(`import ${name} from '../../../components/docs/diagrams/${name}.astro';`);

      for (const slot of ['build', 'needs', 'check']) expect(text).toContain(`slot="${slot}"`);
    });

    it(`${slug}: shows every sample it imports, and keeps the anchors other pages link to`, () => {
      for (const [, variable] of text.matchAll(/^import (\w+) from '[^']+\?raw';$/gmu)) {
        expect(text).toContain(`code={${variable}}`);
      }

      const slugs = [...text.matchAll(/^ *(?:\d+\. +)?#{2,4} (.+)$/gmu)].map((m) => slugOf(m[1] ?? ''));

      for (const anchor of anchors) expect(slugs).toContain(anchor);
    });
  }
});

describe('Node server wiring diagram', () => {
  const drawing = diagram('NodeServerWiring');
  const server = sample('node-server/server.ts');
  const auth = sample('node-server/auth.ts');

  it('draws the steps of handle() in the order server.ts runs them', () => {
    const steps = [...drawing.matchAll(/\{ code: '([^']+)', note:/gu)].map((m) => m[1] ?? '');

    expect(steps).toEqual(['clientIp', 'validateRequest', 'csrfAllowed', 'switch (route)']);
    expect(ascending(positions(server, steps.map((s) => (s.startsWith('switch') ? s : `${s}(`)))))
      .toBe(true);
  });

  it('refuses where server.ts does: a 403 forbidden when CSRF fails', () => {
    expect(server).toContain("if (!csrfOk) return send(res, 403, { error: { code: 'forbidden' } });");
    expect(drawing).toContain("const REFUSAL = '403 forbidden';");
  });

  it('names what buildAuth holds as auth.ts writes it', () => {
    for (const code of ['redisStores', 'prismaStores']) expect(auth).toContain(`${code}(`);
    expect(auth).toMatch(/^ {4}mailer,$/mu);
    expect(auth).toMatch(/^ {4}logger,$/mu);
    expect(auth).toContain('export function buildAuth(mailer: Mailer)');
    expect(drawing).toContain("const AUTH_CODE = 'buildAuth(mailer)';");
  });
});

describe('tRPC wiring diagram', () => {
  const drawing = diagram('TrpcWiring');
  const router = sample('trpc/router.ts');
  const client = sample('trpc/client.ts');
  const middlewares = source('auth-trpc/src/middlewares.ts');
  const errors = source('auth-trpc/src/errors.ts');

  it('splits mutations and queries the way client.ts does', () => {
    expect(client).toContain("condition: (op) => op.type === 'mutation',");
    expect(client).toContain('true: httpLink(');
    expect(client).toContain('false: httpBatchStreamLink(');
  });

  it('draws the chains of login and exportData from router.ts', () => {
    expect(router).toMatch(/login: publicProcedure\s+\.use\(writesCookies\)/u);
    expect(router).toMatch(
      /exportData: protectedProcedure\s+\.use\(freshAuth\('\w+'\)\)\s+\.use\(rateLimited\(/u,
    );
    expect(drawing).toContain("procedure: 'login',");
    expect(drawing).toContain("procedure: 'exportData',");
  });

  it('labels each check with the public code middlewares.ts refuses with', () => {
    expect(middlewares).toContain("throw toTRPCError(fail('forbidden', 'csrf'));");
    expect(middlewares).toContain("throw toTRPCError(fail('session_expired', 'no_session'));");
    expect(middlewares).toContain("throw toTRPCError(fail('fresh_auth_required', 'stale'));");
    expect(middlewares).toMatch(/fail\('rate_limited', `rate_limited:trpc:/u);

    const refusals = [...drawing.matchAll(/refusal: '([a-z_]+)[',]/gu)].map((m) => m[1] ?? '');

    expect(new Set(refusals)).toEqual(
      new Set(['forbidden', 'internal', 'session_expired', 'fresh_auth_required', 'rate_limited']),
    );

    for (const code of refusals.filter((c) => c !== 'internal')) {
      expect(errors).toContain(`  ${code}: '`);
    }
  });
});
